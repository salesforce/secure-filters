/*!
 * Copyright 2013 GoInstant Inc., a salesforce.com company
 * See LICENSE.txt for details.
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
 * certain context. It is _extremely_ important to choose the escaping function
 * that matches the particular context, so example contexts are given for each
 * function.  Beware of subtle differences, e.g. the `jsAttr` filter.
 *
 * In summary:
 * - `html()` - Sanitizes HTML contexts using entity-encoding.
 * - `js()` - Sanitizes JavaScript string contexts using backslash-encoding.
 * - `jsAttr()` - Sanitizes JavaScript string contexts _in an HTML attribute_
 *   using a combination of entity- and backslash-encoding.
 * - `uri()` - Sanitizes URI contexts using percent-encoding.
 */

'use strict';
var secureFilters = exports;

/**
 * Adds this module's filters to ejs.
 *
 * **USAGE**:
 *
 * ```js
 *   var secureFilters = require('secure-filters');
 *   var ejs = secureFilters.configure(require('ejs'));
 * ```
 *
 * @param {Object} ejs the EJS package object
 * @return {Object} the same EJS object
 */
secureFilters.configure = function(ejs) {
  ejs.filters = ejs.filters || {};
  ['html','js','jsAttr','uri'].forEach(function(filterName) {
    ejs.filters[filterName] = secureFilters[filterName];
  });
  return ejs;
};

var AMP_NO_DOUBLE = /&(?!(?:amp|quot|#39|lt|gt);)/g;
var QUOT = /\"/g;
var APOS = /\'/g;
var LT = /</g;
var GT = />/g;
var BS = /\\/g;
var AST = /\*/g;
var TILDE = /~/g;
var BANG = /!/g;
var LPAREN = /\(/g;
var RPAREN = /\)/g;

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
 * @name uri
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the percent-encoded string
 */
secureFilters.uri = function(val) {
  // "encodeURIComponent() will not encode ~!*()'"
  var encode = encodeURIComponent(String(val));
  return encode
    .replace(BANG, '%21')
    .replace(APOS, '%27')
    .replace(LPAREN, '%28')
    .replace(RPAREN, '%29')
    .replace(AST, '%2A')
    .replace(TILDE, '%7E');
};

/**
 * Encodes an object as JSON, but with unsafe characters in string literals
 * backslash-escaped.
 *
 * **USAGE**: all instances of `USERINPUT` should be sanitized by this function
 *
 * ```html
 *   <script>
 *     var config = USERINPUT;
 *   </script>
 * ```
 *
 * No special processing is required to parse the resulting JSON object.
 *
 * Specifically, this function encodes the object with `JSON.stringify()`, then
 * replaces `<>` with `\u003C` and `\u003E`, respectively, to prevent breaking
 * out of the surrounding script context.
 *
 * @name jsObj
 * @param {any} val
 * @return {string} the JSON- and backslash-encoded string
 */
secureFilters.jsObj = function(val) {
  return JSON.stringify(val)
    .replace(LT, '\\u003C')
    .replace(GT, '\\u003E');
};
