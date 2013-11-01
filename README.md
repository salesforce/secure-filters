# secure-filters

`secure-filters` is a collection of sanitization functions ("filters") to
provide protection against [Cross-Site Scripting (XSS)](https://owasp.org/index.php/Cross-site_Scripting_%28XSS%29)
and other injection attacks.

XSS is the [#3 most critical security flaw affecting web
applications](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
for 2013, as determined by a broad consensus among
[OWASP](https://www.owasp.org) members.

To effectively combat XSS, you must combine input validation with output
sanitization. This module aims to provide only output sanitization since there
are plenty of JavaScript modules out there to do the validation part.

Whichever input validation and output sanitization modules you end up using,
please review the code carefully and apply your own professional paranoia.
Trust, but verify.

### Input Validation

You can roll your own input validation or you can use an existing module.  Either way, there are
[many](https://owasp.org/index.php/Data_Validation)
[important](https://goinstant.com/blog/the-importance-of-proper-input-validation-for-security)
[rules](https://owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet) to follow.

[This Stack-Overflow
thread](http://stackoverflow.com/questions/4088723/validation-library-for-node-js)
lists several input validation options specific to node.js.

One of those options is node-validator ([NPM](https://npmjs.org/package/validator),
[github](https://github.com/chriso/node-validator)).
It provides an impressive list of chainable validators. In addition to
validation, it gives a set of handy [sanitization
filters](https://github.com/chriso/node-validator#list-of-sanitization--filter-methods).

Validator has an `xss()` filter function that can strip-out certain _common_ XSS
attack-strings. But, _use caution_: XSS attacks can be so highly obfuscated that
they may be able to [bypass Validator's detection
algorithm](https://nealpoole.com/blog/2013/07/xss-filter-bypass-in-validator-nodejs-module/).
Validator also has a 3rd party
[express-validate](https://github.com/Dream-Web/express-validate) middleware
module for use in the popular [Express](http://expressjs.com/) node.js server.

# Usage

`secure-filters` can be used with EJS or as normal functions.

:warning: **CAUTION**: If the `Content-Type` HTTP header for your document, or
the `<meta charset="">` tag (or eqivalent) specifies a non-UTF-8 encoding these
filters _may not provide adequate protection_! Some browsers can treat some
characters at Unicode code-points `0x00A0` and above as if they were `<` if the
encoding is not set to UTF-8!

## With EJS

To configure EJS, simply wrap your `require('ejs')` call.  This will import the
filters using the names pre-defined by this module.

```js
  var ejs = require('secure-filters').configure(require('ejs'));
```

Then, within an EJS template:

```html
  <script>
    var config = <%-: config |jsObj%>;
    var userId = parseInt('<%-: userId |js%>',10);
  </script>
  <a href="/welcome/<%-: userId |uri%>">Welcome <%-: userName |html%></a>
  <br>
  <a href="javascript:activate('<%-: userId |jsAttr%>')">Click here to activate</a>
```

### Alternative EJS uses.

It's possible that the filter names pre-defined by this module interferes with
existing filters that you've written. Or, you may wish to import a sub-set of
the filters. In which case, you can simply assign properties to the
`ejs.filters` object.

```js
  var secureFilters = require('secure-filters');
  var ejs = require('ejs');
  ejs.filters.secJS = secureFilters.js;
```

```html
  <script>
    var myStr = "<%-: myVal | secJS %>";
  </script>
```

Or, you can namespace using a parametric style, similar to how EJS' pre-defined
`get:'prop'` filter works:

```js
  var secureFilters = require('secure-filters');
  var ejs = require('ejs');
  ejs.filters.sec = function(val, context) {
    return secureFilters[context](val);
  };
```

```html
  <script>
    var myStr = "<%-: myVal | sec:'js' %>";
  </script>
```

## As Normal Functions

The filter functions are just regular functions and can be used outside of EJS.

```js
  var htmlEscape = require('secure-filters').html;
  var escaped = htmlEscape('"><script>alert(\'pwn\')</script>');
  assert.equal(escaped,
    '&quot;&gt;&lt;script&gt;alert&#40;&#39;pwn&#39;&#41;&lt;&#47;script&gt;');
```

# Functions

Available functions:

- [`html(value)`](#htmlvalue) - Sanitizes HTML contexts using entity-encoding.
- [`js(value)`](#jsvalue) - Sanitizes JavaScript string contexts using backslash-encoding.
- [`jsObj(value)`](#jsobjvalue) - Sanitizes JavaScript literals (numbers, strings,
  booleans, arrays, and objects) for inclusion in an HTML script context.
- [`jsAttr(value)`](#jsattrvalue) - Sanitizes JavaScript string contexts _in an HTML attribute_
  using a combination of entity- and backslash-encoding.
- [`uri(value)`](#urivalue) - Sanitizes URI contexts using percent-encoding.
- [`css(value)`](#cssvalue) - Sanitizes CSS contexts using backslash-encoding.
- [`style(value)`](#stylevalue) - Sanitizes CSS contexts _in an HTML `style`
  attribute_ using entity- and backslash-encoding.

By convention in the Contexts below, `USERINPUT` should be replaced with the
output of the filter function.

### html(value)

Sanitizes output for HTML element and attribute contexts using entity-encoding.

Contexts:

```html
  <p>Hello, <span id="name">USERINPUT</span></p>
  <div class="USERINPUT"></div>
  <div class='USERINPUT'></div>
```

:warning: **CAUTION**: this is not the correct encoding for embedding the contents of
a `<script>` or `<style>` block (plus other blocks that cannot have
entity-encoded characters).

Any character not matched by `/[\t\n\v\f\r ,\.0-9A-Z_a-z\-\u00A0-\uFFFF]/` is
replaced with an HTML entity.  Additionally, characters matched by
`/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/` are converted to spaces to avoid
browser quirks that interpret these as non-characters.

#### A Note About `<%= %>`

You might be asking "Why provide `html(var)`? EJS already does HTML escaping!".

At the time of this writing, EJS doesn't escape the `'`
(apostrophe) character when using the `<%= %>` syntax.  This can lead to
XSS accidents!  Consider the template:

```html
  <img src='<%= prefs.avatar %>'>
```

When given user input `x' onerror='alert(1)`, the above gets rendered as:

```html
  <img src='x' onerror='alert(1)'>
```

Which will cause the `onerror` javascript to run.  Using this module's filter
should prevent this.

```html
  <img src='<%-: prefs.avatar |html%>'>
```

When given user input `x' onerror='alert(1)`, the above gets rendered as:

```html
  <img src='x&#39; onerror&#61;&#39;alert&#40;1&#41;'>
```

Which will not run the attacking script.


### js(value)

Sanitizes output for JavaScript _string_ contexts using backslash-encoding.

```html
  <script>
    var singleQuote = 'USERINPUT';
    var doubleQuote = "USERINPUT";
    var anInt = parseInt('USERINPUT', 10);
    var aFloat = parseFloat('USERINPUT');
    var aBool = ('USERINPUT' === 'true');
  </script>
```

:warning: **CAUTION**: you need to always put quotes around the embedded value; don't
assume that it's a bare int/float/boolean constant!

:warning: **CAUTION**: this is not the correct encoding for the entire contents of a
`<script>` block!  You need to sanitize each variable in-turn.

Any character not matched by `/[,\-\.0-9A-Z_a-z]/` is escaped as `\xHH` or
`\uHHHH` where `H` is a hexidecimal digit.  The shorter `\x` form is used for
charaters in the 7-bit ASCII range (i.e. code point <= 0x7F).

### jsObj(value)

Sanitizes output for a JavaScript literal in an HTML script context.

```html
  <script>
    var config = USERINPUT;
  </script>
```

This function encodes the object with `JSON.stringify()`, then
escapes certain characters.  Any character not matched by
`/[",\-\.0-9:A-Z\[\\\]_a-z{}]/` is escaped consistent with the
[`js(value)`](#jsvalue) escaping above. Additionally, the sub-string `]]>` is
encoded as `\x5D\x5D\x3E` to prevent breaking out of CDATA context.

Because `<` and `>` are not matched characters, they get encoded as `\x3C` and
`\x3E`, respectively. This prevents breaking out of a surrounding HTML
`<script>` context.

For example, with a literal object like `{username:'Albert
</script><script>alert("Pwnerton")'}`, `jsObj()` gives output:

```html
  <script>
    var config = {"username":"\x3C\x2Fscript\x3E\x3Cscript\x3Ealert\x28\"Pwnerton\"\x29"};
  </script>
```

#### JSON is not a subset of JavaScript

Article: [JSON isn't a JavaScript
Subset](http://timelessrepo.com/json-isnt-a-javascript-subset).

JSON is _almost_ a subset of JavaScript, but for two characters: [`LINE
SEPARATOR` U+2028](http://www.fileformat.info/info/unicode/char/2028/index.htm)
and [`PARAGRAPH SEPARATOR`
U+2029](http://www.fileformat.info/info/unicode/char/2029/index.htm).  These
two characters can't legally appear in JavaScript strings and must be escaped.
Due to the ambiguity of these and other Unicode whitespace characters,
`secure-filters` will backslash encode U+2028 as `\u2028`, U+2029 as `\u2029`,
etc.

### jsAttr(value)

Sanitizes output for embedded HTML scripting attributes using a special
combination of backslash- and entity-encoding.

```html
  <a href="javascript:doActivate('USERINPUT')">click to activate</a>
  <button onclick="display('USERINPUT')">Click To Display</button>
```

The string `<ha>, 'ha', "ha"` is escaped to `&lt;ha&gt;, \&#39;ha\&#39;,
\&quot;ha\&quot;`. Note the backslashes before the apostrophe and quote
entities.

### uri(value)

Sanitizes output in URI component contexts by using percent-encoding.

```html
  <a href="http://example.com/?this=USERINPUT&that=USERINPUT">
  <a href="http://example.com/api/v2/user/USERINPUT">
```

The ranges 0-9, A-Z, a-z, plus hypen, dot and underscore (`-._`) are
preserved. Every other character is converted to UTF-8, then output as %XX
percent-encoded octets, where X is an uppercase hexidecimal digit.

**Note** that if composing a URL, the entire result should ideally be
HTML-escaped before insertion into HTML. However, since Percent-encoding is
also HTML-safe, it may be sufficient to just URI-encode the untrusted
components if you know the rest is application-supplied.

### css(value)

Sanitizes output in CSS contexts by using backslash encoding.

```html
  <style type="text/css">
    #user-USERINPUT {
      background-color: #USERINPUT;
    }
  </style>
```

**CAUTION** this is not the correct filter for a `style=""` attribute; use
the [`style(value)`](#stylevalue) filter instead!

The ranges a-z, A-Z, 0-9 plus Unicode code points greater than or equal to
U+00A1 are preserved.  All other characters are encoded as `\h `, where `h`
is one one or more lowercase hexadecimal digits, including the trailing
space.

Confusingly, CSS allows `NO-BREAK SPACE` U+00A0 to be used in an identifier.
Because of this confusion, it's possible browsers treat it as whitespace, and
so `secure-filters` escapes it.

Since [the behaviour of NUL in CSS2.1 is
undefined](http://www.w3.org/TR/CSS21/syndata.html#characters), it is replaced
with `\fffd `, `REPLACEMENT CHARACTER` U+FFFD.

For example, the string `<wow>` becomes `\3c wow\3e ` (note the trailing space).

### style(value)

Encodes values for safe embedding in HTML style attribute context.

**USAGE**: all instances of `USERINPUT` should be sanitized by this function

```html
  <div style="background-color: #USERINPUT;"></div>
```

Encodes the value first as in the `css()` filter, then entity-encodes the result.

For example, the string `<wow>` becomes `&#92;3c wow&#92;3e `.

# Contributing

If you'd like to contribute to or modify secure-filters, here's a quick guide
to get you started.

## Development Dependencies

- [node.js](http://nodejs.org) >= 0.10

## Set-Up

Download via GitHub and install npm dependencies:

```sh
git clone git@github.com:goinstant/secure-filters.git
cd secure-filters

npm install
```

## Testing

Testing is with the [mocha](https://github.com/visionmedia/mocha) framework.
Tests are located in the `tests/` directory.

The unit tests are run twice: once under node.js and once under
[PhantomJS](http://phantomjs.org/). PhantomJS test files are located in the
`static/` directory.

To run the tests:

```sh
npm test
```

## Publishing

1. `npm version patch` (increments `x` in `z.y.x`, then makes a commit for package.json, tags that commit)
2. `git push --tags origin master`
3. `npm publish`

Go to https://npmjs.org/package/secure-filters and verify it published (can take several minutes)

# Support

Email [GoInstant Support](mailto:support@goinstant.com) or stop by [#goinstant on freenode](irc://irc.freenode.net#goinstant).

For responsible disclosures, email [GoInstant Security](mailto:security@goinstant.com).

To [file a bug](https://github.com/goinstant/secure-filters/issues) or
[propose a patch](https://github.com/goinstant/secure-filters/pulls),
please use github directly.

# License

&copy; 2013 GoInstant Inc., a salesforce.com company

Licensed under the BSD 3-clause license.
