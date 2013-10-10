# secure-filters

`secure-filters` is a collection of sanitization functions ("filters") to
provide protection against Cross-Site Scripting (XSS) and other injection
attacks.

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
    var userId = parseInt('<%-: userId |js%>',10);
  </script>
  <a href="/welcome/<%-: userId |uri%>">Welcome <%-: userName |html%></a>
```

## As Normal Functions

The filter functions are just regular functions and can be used outside of EJS.

```js
  var htmlEscape = require('secure-filters').html;
  var escaped = htmlEscape('"><script>alert('pwn')</script>');
  assert.equal(escaped,
    '&quot;&gt;&lt;script&gt;alert(&#39;pwn&#39;)&lt;script&gt;');
```

# Functions

Available functions:

- [`html(value)`](#htmlvalue) - Sanitizes HTML contexts using entity-encoding.
- [`js(value)`](#jsvalue) - Sanitizes JavaScript string contexts using backslash-encoding.
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

**CAUTION**: this is not the correct encoding for embedding the contents of
a `<script>` or `<style>` block (plus other blocks that cannot have
entity-encoded characters).

Avoids double-encoding `&quot;`, `&#39;`, `&lt;`, and `&gt;`.

#### A Note About `<%= %>`

You might be asking "Why provide `html(var)`? EJS already does HTML escaping!".

At the time of this writing, EJS doesn't escape the `'`
(apostrophe) character when using the `<%= %>` syntax.  This can lead to
XSS accidents!  Consider the template:

```html
  <div class='<%= prefs.class %>'></div>
```

When given user input `'><script src='pwn.js'></script><div class='`, this gets
rendered as:

```html
  <div class=''><script src='pwn.js'></script><div class=''></div>
```

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

**CAUTION**: you need to always put quotes around the embedded value; don't
assume that it's a bare int/float/boolean constant!

**CAUTION**: this is not the correct encoding for the entire contents of a
`<script>` block!  You need to sanitize each variable in-turn.

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
