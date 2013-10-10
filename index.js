/*!
 * Copyright 2013 GoInstant Inc., a salesforce.com company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @fileOverview
 * Provides secure filtering functions to prevent a variety of injection and XSS
 * (Cross-Site Scripting) attacks.
 *
 * These filters were designed to be used with EJS, but due to their
 * simplicity, can easily be used in other contexts.
 *
 * By convention, `USERINPUT` is the string that is being embedded into a
 * certain context. It is vitally important to choose the function that matches
 * the particular context, so example contexts are given for each function.
 * Beware of subtle differences, e.g. the `jsAttr` filter.
 */

'use strict';
var secureFilters = exports;

var AMP_NO_DOUBLE = /&(?!(?:amp|quot|#39|lt|gt);)/g;
var QUOT = /\"/g;
var APOS = /\'/g;
var LT = /</g;
var GT = />/g;
var BS = /\\/g;
var AST = /\*/g;

/**
 * Encodes values for safe embedding in HTML tags and attributes.
 *
 * **USAGE**: all instances of `USERINPUT` should be sanitized by this function
 *
 * ```html
 *   <p>Hello, <span id="name">USERINPUT</span></p>
 *   <div class="USERINPUT"></div>
 *   <div class='USERINPUT'></div>
 * ```
 *
 * **CAUTION**: this is not the correct encoding for embedding the contents of
 * a `<script>` or `<style>` block (plus other blocks that cannot have
 * entity-encoded characters).
 *
 * Avoids double-encoding `&quot;`, `&#39;`, `&lt;`, and `&gt;`.
 *
 * @name html
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the encoded string
 */
secureFilters.html = function(val) {
  return String(val)
    // & not followed by certain entities:
    .replace(AMP_NO_DOUBLE, '&amp;')
    // then, after we've replaced &, get the rest:
    .replace(QUOT, '&quot;')
    .replace(APOS, '&#39;')
    .replace(LT, '&lt;')
    .replace(GT, '&gt;');
};

/**
 * Encodes values for safe embedding in JavaScript string contexts.
 *
 * **USAGE**: all instances of `USERINPUT` should be sanitized by this function
 *
 * ```html
 *   <script>
 *     var singleQuote = 'USERINPUT';
 *     var doubleQuote = "USERINPUT";
 *     var anInt = parseInt('USERINPUT', 10);
 *     var aFloat = parseFloat('USERINPUT');
 *     var aBool = ('USERINPUT' === 'true');
 *   </script>
 * ```
 *
 * **CAUTION**: you need to always put quotes around the embedded value; don't
 * assume that it's an int/float/boolean bare constant!
 *
 * **CAUTION**: this is not the correct encoding for the entire contents of a
 * `<script>` block!  You need to sanitize each variable in-turn.
 *
 * @name js
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the encoded string
 */
secureFilters.js = function(val) {
  return String(val)
    .replace(BS, '\\\\') // double-backslash.  Must happen first.
    .replace(AST, '\\*')
    .replace(QUOT, '\\"')
    .replace(APOS, "\\'")
    // < and > need unicode escaping to avoid the string '<script>' from
    // breaking out of the surrounding script context.
    .replace(LT, '\\u003C')
    .replace(GT, '\\u003E');
};


/**
 * Encodes values embedded in HTML scripting attributes.
 *
 * **USAGE**: all instances of `USERINPUT` should be sanitized by this function
 *
 * ```html
 *   <a href="javascript:doActivate('USERINPUT')">click to activate</a>
 * ```
 *
 * This is a combination of backslash-encoding and entity-encoding. It
 * simultaneously prevents breaking out of HTML and JavaScript string contexts.
 *
 * For example, the string
 * `<ha>, 'ha', "ha"`
 * is escaped to
 * `&lt;ha&gt;, \&#39;ha\&#39;, \&quot;ha\&quot;`
 *
 * Note the backslashes before the apostrophe and quote entities.
 *
 * @name jsAttr
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the encoded string
 */
secureFilters.jsAttr = function(val) {
  return String(val)
    // & just needs HTML-escaping
    .replace(AMP_NO_DOUBLE, '&amp;')

    // HTML-escape literal " and '
    .replace(QUOT, "&quot;")
    .replace(APOS, "&#39;")

    .replace(BS, '\\\\') // Must happen before other backslash-escaping
    .replace(AST, '\\*')

    // Double-up HTML- and JS-escape quot and apos to prevent recursive
    // breakout. Happens after escaping literal " and ' above so we can
    // JS-escape all instances of the entities.
    .replace(/\&quot;/g, '\\&quot;')
    .replace(/\&#39;/g, '\\&#39;')

    // < and > are only HTML-escaped
    .replace(LT, '&lt;')
    .replace(GT, '&gt;');
};

/**
 * Percent-encodes unsafe characters in URIs.
 *
 * **USAGE**: all instances of `USERINPUT` should be sanitized by this function
 *
 * ```html
 *   <a href="http://example.com/?this=USERINPUT&that=USERINPUT">
 *   <a href="http://example.com/api/v2/user/USERINPUT">
 * ```
 *
 * The ranges 0-9, A-Z, a-z, plus hypen, dot and underscore (`-._`) are
 * preserved. Every other character is converted to UTF-8, then output as %XX
 * percent-encoded octets, where X is an uppercase hexidecimal digit.
 *
 * **Note** that if composing a URL, the entire result should ideally be
 * HTML-escaped before insertion into HTML. However, since Percent-encoding is
 * also HTML-safe, it may be sufficient to just URI-encode the untrusted
 * components if you know the rest is application-supplied.
 *
 * @name jsAttr
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the percent-encoded string
 */
secureFilters.uri = function(val) {
  var output = "";
  var bytes = new Buffer(String(val), 'utf8'); // parse into utf8 bytes

  for (var i = 0; i < bytes.length; i++) {
    var c = bytes[i];
    if (
      (0x30 <= c && c <= 0x39) || // 0 .. 9
      (0x41 <= c && c <= 0x5A) || // A .. Z
      (0x61 <= c && c <= 0x7A) || // a .. z
      (c === 0x2D) || // -
      (c === 0x2E) || // .
      (c === 0x5F)    // _
    ) {
      output += String.fromCharCode(c);
    } else {
      output += (c < 16 ? '%0' : '%') + c.toString(16).toUpperCase();
    }
  }
  
  return output;
};
