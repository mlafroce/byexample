from __future__ import unicode_literals
import re, shlex, argparse, bisect, collections
from .common import tohuman, constant
from .options import OptionParser, UnrecognizedOption, ExtendOptionParserMixin
from .expected import _LinearExpected, _RegexExpected
from .parser_sm import SM_NormWS, SM_NotNormWS


def tag_name_as_regex_name(name):
    return name.replace('-', '_')


TagRegexs = collections.namedtuple('TagRegexs', ['for_split', 'for_capture'])
InputRegexs = collections.namedtuple(
    'InputRegexs', ['for_check', 'for_capture']
)


class ExampleParser(ExtendOptionParserMixin):
    def __init__(self, verbosity, encoding, options, **unused):
        ExtendOptionParserMixin.__init__(self)
        self.verbosity = verbosity
        self.encoding = encoding
        self.options = options

        self._optparser_extended_cache = None
        self._opts_cache = {}

    def __repr__(self):
        return '%s Parser' % tohuman(self.language if self.language else self)

    def example_options_string_regex(self):
        '''
        Return a regular expressions to extract a string that contains all
        the options of the example.

        This regex will be used once per example and it must have an
        unnamed group.

        Example:
          #  byexample: bla bla
          /* byexample: bla bla
          # ~byexample~ bla bla

        '''
        raise NotImplementedError()  # pragma: no cover

    def example_options_as_list(self, string):
        '''
        Return a list of tokens from the string that was captured by
        the regex of example_options_string_regex.

        For example:
         '-foo a +bar "1 2 3"' should yield [-foo, a, +bar, "1 2 3"]
        '''
        return shlex.split(string)

    def extend_option_parser(self, parser):
        '''
        See options.ExtendOptionParserMixin.

        By default do not add any new flag.
        '''
        return parser

    @constant
    def capture_tag_regexs(self):
        '''
        Return a set of regular expressions to match a 'capture tag'.

        Due implementation details the underscore character '_'
        *cannot* be used as a valid character in the name.
        Instead you should use minus '-'.

        The returned regex can be used for splitting a string
        or for capturing.
        '''
        open, close = map(re.escape, '<>')

        name_re = r'[A-Za-z.][A-Za-z0-9:.-]*'
        return TagRegexs(
            for_split=re.compile(r"(%s%s%s)" % (open, name_re, close)),
            for_capture=re.compile(
                r"%s(?P<name>%s)%s" % (open, name_re, close)
            )
        )

    @constant
    def input_regexs(self):
        open, close = map(re.escape, '[]')
        input_re = r'''
            %s          # open marker
            (?P<input>
            [^%s\\]*    # neither a close marker or a slash
            (?:\\.[^%s\\]*)*    # a "escaped" char followed by
                                # 0 or more "neither a close marker or a slash"
            )
            %s          # a close marker
            ''' % (open, close, close, close)

        input_re_at_end = r'''
            %s          # the input regex
            (?P<trailing>
                [ ]*$   # followed by some optional space and a end of line
            )
            ''' % (input_re)

        return InputRegexs(
            for_check=re.compile(input_re, re.VERBOSE | re.MULTILINE),
            for_capture=re.compile(input_re_at_end, re.VERBOSE | re.MULTILINE)
        )

    def ellipsis_marker(self):
        return '...'

    def process_snippet_and_expected(self, snippet, expected):
        r'''
        Process the snippet code and the expected output.

        Take this opportunity to do any processing after the parsing of
        the example (in particular, after the extraction of the options)

        By default, the snippet will end with a new line: most of the
        runners use this to flush and execute the code.
        '''

        if not expected:
            expected = ''  # make sure that it is an empty string

        if not snippet.endswith('\n'):
            snippet += '\n'  # make sure that we end the code with a newline
            # most of the runners use this to flush and
            # execute the code

        return snippet, expected

    def parse(self, example, concerns):
        options = self.options

        local_options = self.extract_options(example.snippet)
        options.up(local_options)

        example.source, example.expected_str = self.process_snippet_and_expected(
            example.snippet, example.expected_str
        )

        # the options to customize this example
        example.options = local_options

        if concerns:
            concerns.before_build_regex(example, options)

        for x in options['rm']:
            example.expected_str = example.expected_str.replace(x, '')

        expected_regexs, charnos, rcounts, tags_by_idx, input_list = self.expected_as_regexs(
            example.expected_str, options['tags'], options['type'], options['norm_ws']
        )

        ExpectedClass = _LinearExpected

        expected = ExpectedClass(
            # the output expected
            expected_str=example.expected_str,

            # expected regex version
            regexs=list(expected_regexs),

            # where each regex comes from
            charnos=list(charnos),

            # the 'real count' of literals
            rcounts=list(rcounts),

            # all the regexs that are not literal (tags) indexed
            # by their position in the regex list.
            # we don't save the regex (use 'regexs' for that),
            # instead save the name of the tag or None if it's
            # unnamed
            tags_by_idx=tags_by_idx,
        )

        # the source code to execute and the expected
        example.expected = expected

        # a list with the input to type and their prefixes
        # to know "where/when" we should type
        example.input_list = input_list

        options.down()
        return example

    def expected_as_regexs(self, expected, tags_enabled, input_enabled, normalize_whitespace):
        '''
        From the expected string create a list of regular expressions that
        joined with the flags re.MULTILINE | re.DOTALL, matches
        that string.

        This method returns four things:
            - a list of regexs: for literals, captures, wildcards, ...
            - a list with the character numbers, the positions in the expected
              string from where it was created each regex
            - a list of rcounts (see below)
            - a dict of non-literal 'regexs' names (capturing and non-capturing)
              also know as "tags" indexed by position.
              For non-capturing the name will be None.

            >>> from byexample.parser import ExampleParser
            >>> import re

            >>> parser = ExampleParser(0, 'utf8', None); parser.language = 'python'
            >>> _as_regexs = parser.expected_as_regexs

            >>> expected = 'a<foo>b<bar>c'
            >>> regexs, charnos, rcounts, tags_by_idx, input_list = _as_regexs(expected, True, True, False)

        We return the regexs

            >>> regexs
            ('\\A', 'a', '(?P<foo>.*?)', 'b', '(?P<bar>.*?)', 'c', '\\n*\\Z')

            >>> m = re.compile(''.join(regexs), re.MULTILINE | re.DOTALL)
            >>> m.match('axxbyyyc').groups()
            ('xx', 'yyy')

        And we can see the charnos or the position in the original expected
        string from where each regex was built

            >>> charnos
            (0, 0, 1, 6, 7, 12, 13)

            >>> len(expected) == charnos[-1]
            True

        And the rcount of each regex. A rcount or 'real count' count how many
        literals are. See _as_safe_regexs for more information about this but
        in a nutshell, rcount == len(line) if normalize_whitespace is False;
        if not, it is the len(line) but counting the secuence of whitespaces as
        +1.

        And we can see the positions of the tags in the regex list
        of all the non-literal regexs or "tags". The value of each
        item is the name of tag or None if it is unnamed

            >>> tags_by_idx
            {2: 'foo', 4: 'bar'}

        The following example shows what happen when we use a non-capturing tag
        (ellipsis tag) also known as unnamed tag and what happen when we use
        a tag name with a - (Python regexs don't support this character) and
        we enable the normalization of the whitespace:

            >>> expected = 'a<...> <foo-bar>c'
            >>> regexs, _, _, tags_by_idx, input_list = _as_regexs(expected, True, True, True)

            >>> regexs          # byexample: +norm-ws
            ('\\A', 'a', '(?:.*?)(?<!\\s)', '\\s+(?!\\s)', '(?P<foo_bar>.*?)', 'c', '\\s*\\Z')

            >>> tags_by_idx
            {2: None, 4: 'foo-bar'}
        '''
        if normalize_whitespace:
            sm = SM_NormWS(
                self.capture_tag_regexs(), self.input_regexs(),
                self.ellipsis_marker(), (6, 12)
            )
        else:
            sm = SM_NotNormWS(
                self.capture_tag_regexs(), self.input_regexs(),
                self.ellipsis_marker(), (6, 12)
            )

        return sm.parse(expected, tags_enabled, input_enabled)

    def extract_cmdline_options(self, opts_from_cmdline):
        # now we can re-parse this argument 'options' from the command line
        # this will enable the user to set some options for a specific language
        #
        # we parse this non-strictly because the 'options' string from the
        # command line may contain language-specific options for other
        # languages than this parser (self) is targeting.
        optparser = self.options['optparser']
        optparser_extended = self.get_extended_option_parser(optparser)
        return optparser_extended.parse(opts_from_cmdline, strict=False)

    def extract_options(self, snippet):
        optstring_match = self.example_options_string_regex().search(snippet)

        if not optstring_match:
            optlist = []

        else:
            optlist = self.example_options_as_list(optstring_match.group(1))

        if not isinstance(optlist, list):
            raise ValueError(
                "The option list returned by the parser is not a list!. This probably means that there is a bug in the parser %s."
                % str(self)
            )

        return self._extend_parser_and_parse_options_strictly_and_cache(
            optlist
        )

    def _extend_parser_and_parse_options_strictly(self, optlist):
        # we parse the example's options
        # in this case, at difference with extract_cmdline_options,
        # we parse it strictly because the example's options
        # must contain options standard of byexample and/or standard of this
        # parser (self)
        # any other options is an error
        optparser = self.options['optparser']
        optparser_extended = self.get_extended_option_parser(optparser)
        try:
            opts = optparser_extended.parse(optlist, strict=True)
        except UnrecognizedOption as e:
            raise ValueError(str(e))

        return opts

    def _extend_parser_and_parse_options_strictly_and_cache(self, optlist):
        ''' This is a thin wrapper around _extend_parser_and_parse_options_strictly
            to cache its results based on the optlist.

            Note that two different lists may represent the same options set
            like:
                l1 = [-foo, a, +bar, "1 2 3"]   => -foo=1 and +bar="1 2 3"
                l2 = [+bar, "1 2 3", -foo, a]   => -foo=1 and +bar="1 2 3"

            This cache system is very naive and will save two entries for
            those.

            And it works under the assumption that if a given example's options
            were parsed by X extended parser, the *same* options of another
            example *would* be parsed by the same *X parser* and it *would*
            yield the *same* result.

            If the parser object or its behaviour changes in runtime, you
            will need to override this method and change or disable the cache.
            '''
        try:
            return self._opts_cache[tuple(optlist)]
        except KeyError:
            val = self._extend_parser_and_parse_options_strictly(optlist)
            self._opts_cache[tuple(optlist)] = val
            return val

    def extract_input_list(self, expected_str, tmp):
        ''' Extract a list of (prefix, input) tuples from the expected
            output of the example (<expected_str>).

            The <input> are the strings to be typed in during the
            execution of the examples; the <prefix> are the expected
            output that should appear before.

            >>> from byexample.parser import ExampleParser
            >>> from functools import partial

            >>> parser = ExampleParser(0, 'utf8', None); parser.language = 'python'
            >>> _regexs = partial(parser.expected_as_regexs, tags_enabled=True, normalize_whitespace=False)
            >>> _inputs = parser.extract_input_list

            >>> expected = 'foo [bar] baz'
            >>> _inputs(expected, _regexs(expected))
            [('foo ', 'bar')]

            >>> expected = 'foo [bar] baz [bla]'
            >>> _inputs(expected, _regexs(expected))
            [('foo ', 'bar'), (' baz ', 'bla')]

            >>> expected = '[bar] baz [bla]'
            >>> _inputs(expected, _regexs(expected))
            [('', 'bar'), (' baz ', 'bla')]

            >>> expected = 'foo [bar][bla]'
            >>> _inputs(expected, _regexs(expected))
            [('foo ', 'bar'), ('', 'bla')]


            >>> expected = 'foo <tag> zaz [bar]'
            >>> _inputs(expected, _regexs(expected))
            [(' zaz ', 'bar')]

            >>> expected = 'foo <tag>y<tag2> zaz [bar]'
            >>> _inputs(expected, _regexs(expected))
            [(' zaz ', 'bar')]

            >>> expected = 'foo <tag>x<tag2>yy<tag3> zaz [bar]<tag4>q[zaz]'
            >>> _inputs(expected, _regexs(expected))
            [(' zaz ', 'bar'), ('q', 'zaz')]

            >>> expected = 'foo [<tag>] [bla]'
            >>> _inputs(expected, _regexs(expected))
            Error. The following tags were found inside of a type tag:
            tag
            [('foo ', '<tag>'), (' ', 'bla')]
            '''
        regexs, charnos, _, tags_by_idx = tmp
        tag_by_charno = {charnos[ix]: tag for ix, tag in tags_by_idx.items()}
        tag_charnos = list(sorted(tag_by_charno.keys()))

        input_list = []
        prefix = None

        charno = 0
        for i, token in enumerate(self.input_regex().split(expected_str)):
            token_is_an_input = i % 2 == 1
            if token_is_an_input:
                input = token
                assert prefix is not None

                # this "+2" counts the [ and ] markers
                nextcharno = charno + len(input) + 2

            else:
                output = token
                nextcharno = charno + len(output)

            # Range (left-inclusive, right-inclusive) of charnos of
            # tags that are between the current charno and the next one
            # (tags that are "inside" of our current "token"
            #
            # charno <= tag_charnos[r] <= nextcharno <= tag_charnos[l]

            # tag_charnos[:r] < charno <= tag_charnos[r:]
            r = bisect.bisect_left(tag_charnos, charno)

            # tag_charnos[:l] < nextcharno <= tag_charnos[l:]
            l = bisect.bisect_left(tag_charnos, nextcharno)

            # tag_charnos[r:l] now contains the charno of each tag that are
            # "inside" of the current "token"
            tag_charnos_inside = tag_charnos[r:l]

            if token_is_an_input:
                if tag_charnos_inside:
                    print(
                        "Error. The following tags were found inside of a type tag: "
                    )
                    print(
                        ', '.join(
                            tag_by_charno[c] for c in tag_charnos_inside
                        )
                    )

                input_list.append((prefix, input))

                charno = nextcharno
            else:
                if not tag_charnos_inside:
                    literal_output = output
                else:
                    nearest_tag_at = tag_charnos_inside[-1]

                    # / charno      / nextcharno
                    # |             |
                    # www <foo> xxx [bar] yyy <zaz>
                    #     |
                    #     \ nearest_tag_at

                    # this "+2" counts the < and > markers
                    tag_len = len(tag_by_charno[nearest_tag_at]) + 2

                    literal_output_len = (
                        nextcharno - nearest_tag_at - tag_len
                    )
                    literal_output = output[-literal_output_len:]

                prefix = literal_output  # TODO check len, emptyness, etc
                charno = nextcharno

        return input_list


# Extra tests
'''
>>> expected = 'ex <...>\nu<...>'
>>> regexs, _, _, _, _ = _as_regexs(expected, True, True, True)

>>> regexs
('\\A',
 'ex',
 '\\s',
 '(?:\\s*(?!\\s)(?:.+)(?<!\\s))?',
 '\\s+(?!\\s)',
 'u',
 '(?:.*)(?<!\\s)',
 '\\s*\\Z')

>>> m = re.compile(''.join(regexs), re.MULTILINE | re.DOTALL)
>>> m.match('ex  x\n  u  \n').groups()
()

>>> expected = 'ex <foo>\nu<bar>'
>>> regexs, _, _, _, _ = _as_regexs(expected, True, True, True)

>>> regexs
('\\A',
 'ex',
 '\\s',
 '(?:\\s*(?!\\s)(?P<foo>.+?)(?<!\\s))?',
 '\\s+(?!\\s)',
 'u',
 '(?P<bar>.*?)(?<!\\s)',
 '\\s*\\Z')

>>> m = re.compile(''.join(regexs), re.MULTILINE | re.DOTALL)
>>> m.match('ex  x\n  u  \n').groups()
('x', '')

'''
