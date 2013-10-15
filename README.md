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

### Input Validation

You can roll your own input validation or you can use an existing module.  Either way, there are
[many](https://owasp.org/index.php/Data_Validation)
[important](https://goinstant.com/blog/the-importance-of-proper-input-validation-for-security)
[rules](https://owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet) to follow.

http://stackoverflow.com/questions/4088723/validation-library-for-node-js lists
several input validation options specific to node.js.

One of those options is node-validator ([NPM](https://npmjs.org/package/validator),
[github](https://github.com/chriso/node-validator)).
It provides an impressive list of chainable validators. In addition to
validation, it gives a set of handy [sanitization
filters](https://github.com/chriso/node-validator#list-of-sanitization--filter-methods).
There's even an `xss()` filter function that can strip-out certain _common_ XSS
attack-strings. But, use caution: XSS attacks can be so highly obfuscated that
they may be able to bypass Validator's detection algorithm. Validator also has
a 3rd party [express-validate](https://github.com/Dream-Web/express-validate)
middleware module for use in the popular [Express](http://expressjs.com/)
node.js server.

# Usage

`secure-filters` can be used with EJS or as normal functions.

## With EJS

To configure EJS, simply wrap your `require('ejs')` call:

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

## As Normal Functions

The filter functions are just regular functions and can be used outside of EJS.

```js
  var htmlEscape = require('secure-filters').html;
  var escaped = htmlEscape('"><script>alert(\'pwn\')</script>');
  assert.equal(escaped,
    '&quot;&gt;&lt;script&gt;alert(&#39;pwn&#39;)&lt;script&gt;');
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

Avoids double-encoding `&quot;`, `&#39;`, `&lt;`, and `&gt;`.

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

Which will cause the `onerror` javascript to run.  Using this module's filter should prevent this.

```html
  <img src='<%-: prefs.avatar |html%>'>
```

When given user input `x' onerror='alert(1)`, the above gets rendered as:

```html
  <img src='x&#39; onerror=&#39;alert(1)'>
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

The `<` and `>` characters are encoded as `\u003C` and `\u003E`, respectively.
This prevents breaking out of a surrounding `<script>` context.

:warning: **CAUTION**: you need to always put quotes around the embedded value; don't
assume that it's a bare int/float/boolean constant!

:warning: **CAUTION**: this is not the correct encoding for the entire contents of a
`<script>` block!  You need to sanitize each variable in-turn.

### jsObj(value)

Sanitizes output for a JavaScript literal in an HTML script context.

```html
  <script>
    var config = USERINPUT;
  </script>
```

Specifically, this function encodes the object with `JSON.stringify()`, then
replaces `<` with `\u003C` and `>` with `\u003E` to prevent breaking
out of the surrounding script context.

For example, with a literal object like `{username:'Albert
</script><script>alert("Pwnerton")'}`, gives output:

```html
  <script>
    var config = {"username":"\u003C/script\u003E\u003Cscript\u003Ealert(\"Pwnerton\")"};
  </script>
```

### jsAttr(value)

Sanitizes output for embedded HTML scripting attributes using a special
combination of backslash- and entity-encoding.

```html
  <a href="javascript:doActivate('USERINPUT')">click to activate</a>
```

The string `<ha>, 'ha', "ha"` is escaped to `&lt;ha&gt;, \&#39;ha\&#39;, \&quot;ha\&quot;`. Note the backslashes before the apostrophe and quote entities.

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

# Contact

For questions, comments, and responsible disclosures, please contact
<a href="mailto:security@goinstant.com">security@goinstant.com</a>.

# License

Copyright 2013 GoInstant Inc., a salesforce.com company

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
