# secure-filters

`secure-filters` is a collection of Output Sanitization functions ("filters")
to provide protection against [Cross-Site Scripting
(XSS)](https://owasp.org/index.php/Cross-site_Scripting_%28XSS%29) and other
injection attacks.

[![Build Status](https://travis-ci.org/salesforce/secure-filters.png?branch=master)](https://travis-ci.org/salesforce/secure-filters)

![Data Flow Diagram](./images/secure-filters%20data%20flow.png)

### Table of select contents

- [About XSS](#about-xss)
- [Usage](#usage)
  - [Installation](#installation) - `npm install --save secure-filters`
  - [EJS](#with-ejs)
  - [Normal functions](#as-normal-functions)
  - [Client-side](#client-side)
- [Functions](#functions)
  - [`html(value)`](#htmlvalue) - Sanitizes HTML contexts using entity-encoding.
  - [`js(value)`](#jsvalue) - Sanitizes JavaScript string contexts using backslash-encoding.
  - [`jsObj(value)`](#jsobjvalue) - Sanitizes JavaScript literals (numbers, strings,
    booleans, arrays, and objects) for inclusion in an HTML script context.
  - [`jsAttr(value)`](#jsattrvalue) - Sanitizes JavaScript string contexts _in an HTML attribute_
    using a combination of entity- and backslash-encoding.
  - [`uri(value)`](#urivalue) - Sanitizes URI contexts using percent-encoding.
  - [`css(value)`](#cssvalue) - Sanitizes CSS contexts using backslash-encoding.
  - [`style(value)`](#stylevalue) - Sanitizes CSS contexts _in an HTML `style` attribute_
- [Contributing](#contributing)
- [Support](#support)
- [Legal](#legal)

# About XSS

XSS is the [#3 most critical security flaw affecting web
applications](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_%28XSS%29)
for 2013, as determined by a broad consensus among
[OWASP](https://www.owasp.org) members.

To effectively combat XSS, you must combine Input Validation with Output
Sanitization.  **Using one or the other is not sufficient; you must apply
both!**  Also, simple validations like string length aren't as effective; it's
much safer to use _whitelist-based validation_.

The generally accepted flow in preventing XSS looks like this:

![Data Flow Diagram](./images/secure-filters%20data%20flow.png)

Whichever Input Validation and Output Sanitization modules you end up
using, please review the code carefully and apply your own professional
paranoia. Trust, but verify.

### Input Validation

`secure-filters` doesn't deal with Input Validation, only Ouput Sanitization.

You can roll your own input validation or you can use an existing module.
Either way, there are
[many](https://owasp.org/index.php/Data_Validation)
[important](https://owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
rules to follow.

[This Stack-Overflow
thread](http://stackoverflow.com/questions/4088723/validation-library-for-node-js)
lists several input validation options specific to node.js.

One of those options is node-validator
([NPM](https://npmjs.org/package/validator),
[github](https://github.com/chriso/node-validator)).  It provides an impressive
list of chainable validators.  Validator also has a 3rd party
[express-validate](https://github.com/Dream-Web/express-validate) middleware
module for use in the popular [Express](http://expressjs.com/) node.js server.

Input Validation can be specialized to the data format.  For example, the
jsonschema module ([NPM](https://npmjs.org/package/jsonschema),
[github](https://github.com/tdegrunt/jsonschema)) can be useful for providing
strict validation of JSON documents (e.g. bodies in HTTP).

### Output Sanitization

Output Sanitization (also known as Ouput Filtering) is what `secure-filters` is
responsible for.

In order to properly santize output you need to be sensitive to the _context_
in which the data is being output. For example, if you want to place text in an
HTML document, you should HTML-escape the text.

But what about CSS or JavaScript contexts? You can't use the HTML-escape
filter; a different escaping method is necessary. If the filter doesn't match
the context, it's possible for browsers to misinterpret the result, which can
lead to XSS attacks!

`secure-filters` aims to provide the filter functions necessary to do this type
of context-sensitive sanitization.

### Hybrid Sanitization

"Sanitization" is an overloaded term and can be confused with other security
techniques.

For example, if you need to store and sanitize HTML, you'd want to parse,
validate and sanitize that HTML in one hybridized step.  There are tools like
[Google Caja](http://code.google.com/p/google-caja/) to do HTML sanitization.
The [`sanitizer` module](https://github.com/theSmaw/Caja-HTML-Sanitizer)
packages-up Caja for node.js/CommonJS usage.

# Usage

`secure-filters` can be used with EJS or as normal functions.

## Installation

```sh
  npm install --save secure-filters
```

:warning: **CAUTION**: If the `Content-Type` HTTP header for your document, or
the `<meta charset="">` tag (or eqivalent) specifies a non-UTF-8 encoding these
filters _may not provide adequate protection_! Some browsers can treat some
characters at Unicode code-points `0x00A0` and above as if they were `<` if the
encoding is not set to UTF-8!

## General Usage

[![Cheat Sheet](./images/secure-filters%20cheat%20sheet.png)](./images/secure-filters%20cheat%20sheet.png)

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

There's a handy [cheat sheet](./cheatsheet.md) showing all the filters in EJS syntax.

### Alternative EJS uses.

Rather than importing the pre-defined names we've chosen, here are some other
ways to integrate `secure-filters` with EJS.

#### Replacing EJS's default escape

As of EJS 0.8.4, you can replace the `escape()` function during template
compilation.  This allows `<%= %>` to be safer than [the
default](#a-note-about--).

```js
var escapeHTML = secureFilters.html;
var templateFn = ejs.compile(template, { escape: escapeHTML });
```

#### One-by-one

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

#### Parametric

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

## Client-side

You can simply include the `lib/secure-filters.js` file itself to get started.

```html
  <script type="text/javascript" src="path/to/secure-filters.js"></script>
  <script type="text/javascript">
    var escaped = secureFilters.html(userInput);
    //...
  </script>
```

We've also added [AMD module
definition](https://github.com/amdjs/amdjs-api/wiki/AMD) to `secure-filters.js`
for use in [Require.js](http://requirejs.org) and other AMD frameworks. We
don't pre-define a name, but suggest that you use 'secure-filters'.

# Functions

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

[Prior to 0.8.5](https://github.com/visionmedia/ejs/blob/master/History.md#085--2013-11-21),
EJS doesn't escape the `'` (apostrophe) character when using the `<%= %>`
syntax.  This can lead to XSS accidents!  Consider the template:

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

### json(value)

Sanitizes output for a JSON string in an HTML script context.

```html
  <script>
    var config = USERINPUT;
  </script>
```

This function escapes certain characters within a JSON string.  Any character
not matched by `/[",\-\.0-9:A-Z\[\\\]_a-z{}]/` is escaped consistent with the
[`js(value)`](#jsvalue) escaping above. Additionally, the sub-string `]]>` is
encoded as `\x5D\x5D\x3E` to prevent breaking out of CDATA context.

Because `<` and `>` are not matched characters, they get encoded as `\x3C` and
`\x3E`, respectively. This prevents breaking out of a surrounding HTML
`<script>` context.

For example, with a JSON string like `'{"username":"Albert </script><script>alert(\"Pwnerton\")"}'`,
`json()` gives output:

```html
  <script>
    var config = {"username":"\x3C\x2Fscript\x3E\x3Cscript\x3Ealert\x28\"Pwnerton\"\x29"};
  </script>
```

### jsObj(value)

Sanitizes output for a JavaScript literal in an HTML script context.

```html
  <script>
    var config = USERINPUT;
  </script>
```

This function encodes the object with `JSON.stringify()`, then
escapes using `json()` detailed above.

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

:warning: **CAUTION** this is not the correct filter for a `style=""` attribute; use
the [`style(value)`](#stylevalue) filter instead!

:warning: **CAUTION** even though this module prevents breaking out of CSS
context, it is still somewhat risky to allow user-controlled input into CSS and
`<style>` blocks. Be sure to combine CSS escaping with _whitelist-based_ input
sanitization! Here's a small sampling of what's possible:

- https://www.computerworld.com/s/article/9221043/Opera_denies_refusing_to_patch_critical_vulnerability
- http://html5sec.org/#43 - note the modern browser versions!


The ranges a-z, A-Z, 0-9 plus Unicode U+10000 and higher are preserved.  All
other characters are encoded as `\h `, where `h` is one one or more lowercase
hexadecimal digits, including the trailing space.

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

:warning: **CAUTION** even though this module prevents breaking out of style-attribute
context, it is still somewhat risky to allow user-controlled input (see caveats
on [css](#cssvalue) above).  Be sure to combine with _whitelist-based_ input
sanitization!

Encodes the value first as in the `css()` filter, then HTML entity-encodes the result.

For example, the string `<wow>` becomes `&#92;3c wow&#92;3e `.

# Contributing

Please see the [Contribution Guide](./contributing.md).

# Support

Support is provided via [github issues](https://github.com/salesforce/secure-filters/issues).

For responsible disclosures, email [Salesforce Security](mailto:security@salesforce.com).

# Changelog

#### 1.1.0

This release changes the behavior of secure-filters, but should be
backwards-compatible with 1.0.5.

- The `js`, `jsObj` and `jsAttr` filter now use a strict allow-list for
  characters in strings.  This is safer, but does increase the size of these
  strings slightly.  Compliant JSON and JavaScript parsers will not be affected
  negatively by this change.
- The example for `jsAttr` was incorrect.  It previously stated that `<ha>,
  'ha', "ha"` was escaped to `&lt;ha&gt;, \&#39;ha\&#39;, \&quot;ha\&quot;`

#### 1.0.5

- Vastly improved documentation and illustrations

#### 1.0.4

- Initial public release

# Legal

&copy; 2014 salesforce.com

Licensed under the BSD 3-clause license.
