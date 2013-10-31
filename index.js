/*!
 * Copyright 2013 GoInstant Inc., a salesforce.com company
 * See LICENSE.txt for details.
 */
(function(root) {
/*global define,module */
'use strict';
var secureFilters = {};
secureFilters.constructor = function secureFilters(){};

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
 * - `jsObj()` - Sanitizes JavaScript objects for inclusion in HTML-script
 *   context.
 * - `uri()` - Sanitizes URI contexts using percent-encoding.
 */

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
  ['html','js','jsAttr','uri','jsObj'].forEach(function(filterName) {
    ejs.filters[filterName] = secureFilters[filterName];
  });
  return ejs;
};

var QUOT = /\x22/g; // "
var APOS = /\x27/g; // '
var LT = /</g;
var GT = />/g;
var AST = /\*/g;
var TILDE = /~/g;
var BANG = /!/g;
var LPAREN = /\(/g;
var RPAREN = /\)/g;
var CDATA_CLOSE = /\]\]>/g;

// Matches alphanum plus ",._-" & unicode.
// ESAPI doesn't consider "-" safe, but we do. It's both URI and HTML safe.
// XXX: the 00A1-FFFF range can't be modified without changes to the code; see
// below.
var JS_NOT_WHITELISTED = /[^,\.0-9A-Z_a-z\-\u00A1-\uFFFF]/g;

// Control characters that get converted to spaces.
var HTML_CONTROL = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;

// Matches alphanum plus allowable whitespace, ",._-", and unicode.
// XXX: the 00A1-FFFF range can't be modified without changes to the code; see
// below.
var HTML_NOT_WHITELISTED = /[^\t\n\v\f\r ,\.0-9A-Z_a-z\-\u00A1-\uFFFF]/g;

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
 * @name html
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the encoded string
 */
secureFilters.html = function(val) {
  var str = String(val);
  str = str.replace(HTML_CONTROL, ' ');
  return str.replace(HTML_NOT_WHITELISTED, function(match) {
    var code = match.charCodeAt(0);
    switch(code) {
    // folks expect these "nice" entities:
    case 0x22:
      return '&quot;';
    case 0x26:
      return '&amp;';
    case 0x3C:
      return '&lt;';
    case 0x3E:
      return '&gt;';

    default:
      // optimize for size:
      if (code < 100) {
        var dec = code.toString(10);
        return '&#'+dec+';';
      } else {
        // XXX: this doesn't produce strictly valid entities for code-points
        // requiring a UTF-16 surrogate pair. However, browsers are generally
        // tolerant of this. Surrogate pairs are currently in the whitelist
        // defined via HTML_NOT_WHITELISTED.
        var hex = code.toString(16).toUpperCase();
        return '&#x'+hex+';';
      }
    }
  });
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
 * Any character that's not alphanumeric or `,-._` will be backslash encoded as
 * `\xHH`. U+00A0 and higher are encoded as `\uHHHH` instead. `H` is a
 * hexadecimal digit.
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
  var str = String(val);
  return str.replace(JS_NOT_WHITELISTED, function(match) {
    var code = match.charCodeAt(0);
    var hex = code.toString(16).toUpperCase();
    if (code < 0x80) { // ASCII
      if (hex.length === 1) {
        return '\\x0'+hex;
      } else {
        return '\\x'+hex;
      }
    } else { // Unicode
      // XXX: with the current definition of JS_NOT_WHITELISTED this block is
      // unused. The Block is left in so that if the regex changes Unicode
      // characters are encoded correctly.  It's also possible that "illegal"
      // chars in the 0x80-0xA0 range get passed in (e.g. CP-1251), in which
      // case we still want to produce sanitary output.
      switch(hex.length) {
      case 2:
        return '\\u00'+hex;
      case 3:
        return '\\u0'+hex;
      case 4:
        return '\\u'+hex;
      default:
        // charCodeAt() JS shouldn't return code > 0xFFFF, and only four hex
        // digits can be encoded via `\u`-encoding, so return REPLACEMENT
        // CHARACTER U+FFFD.
        return '\\uFFFD';
      }
    }
  });
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
 * `\x3Cha\x3E, \&#39;ha\&#39;, \&quot;ha\&quot;`
 *
 * Note the backslashes before the apostrophe and quote entities.
 *
 * @name jsAttr
 * @param {any} val will be converted to a String prior to encoding
 * @return {string} the encoded string
 */
secureFilters.jsAttr = function(val) {
  return secureFilters.html(secureFilters.js(val));
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
  // encodeURIComponent() is well-standardized across browsers and it handles
  // UTF-8 natively.  It will not encode "~!*()'", so need to replace those here.
  // encodeURIComponent also won't encode ".-_", but those are known-safe.
  var encode = encodeURIComponent(String(val));
  return encode
    .replace(BANG, '%21')
    .replace(QUOT, '%27')
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
 * replaces `<>` with `\x3C` and `\x3E`, respectively, to prevent breaking
 * out of the surrounding script context.  `]]>` is converted to `\x5D\x5D\x3E` to
 * prevent breaking out of a CDATA context.
 *
 * @name jsObj
 * @param {any} val
 * @return {string} the JSON- and backslash-encoded string
 */
secureFilters.jsObj = function(val) {
  return JSON.stringify(val)
    // prevent breaking out of CDATA context.  Escaping < below is sufficient
    // to prevent opening a CDATA context.
    .replace(CDATA_CLOSE, '\\x5D\\x5D\\x3E')
    // prevent breaking out of <script> context
    .replace(LT, '\\x3C')
    .replace(GT, '\\x3E');
};


// AMD / RequireJS
if (typeof define !== 'undefined' && define.amd) {
  define([], function () {
    return secureFilters;
  });
}
// CommonJS / Node.js
else if (typeof module !== 'undefined' && module.exports) {
  module.exports = secureFilters;
}
// included directly via <script> tag
else {
  root.secureFilters = secureFilters;
}

}(this));
