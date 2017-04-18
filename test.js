/*!
 * Copyright (c) 2014, Salesforce.com, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of Salesforce.com, nor the names of its contributors may
 *   be used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
(function(root) {
'use strict';

var assert;
var secureFilters;
var _;

if (typeof module !== 'undefined' && module.exports) {
  assert = require('assert');
  secureFilters = require('./index');
  _ = require('underscore');
} else {
  assert = root.assert;
  secureFilters = root.secureFilters;
  _ = root._;
}

// Test character inside the Unicode BMP:
var SNOWMAN = "\u2603";
// Test character outside of the Unicode BMP:
var FACE_WITHOUT_MOUTH = "\uD83D\uDE36"; // U+1F636, UTF-16: D83D DE36, UTF-8: F0 9F 98 B6

var ASCII = "\0";
for (var i = 1; i <= 0x7F; i++) {
  ASCII += String.fromCharCode(i);
}

var ALL_CASES = [
  {
    input: '&&amp;\'d',
    html: '&amp;&amp;amp&#59;&#39;d',
    js: '\\x26\\x26amp\\x3B\\x27d',
    jsAttr: '&#92;x26&#92;x26amp&#92;x3B&#92;x27d',
    uri: '%26%26amp%3B%27d',
    css: '\\26 \\26 amp\\3b \\27 d',
    style: '&#92;26 &#92;26 amp&#92;3b &#92;27 d'
  },
  {
    input: '\' onload="alert(1)"',
    html: '&#39; onload&#61;&quot;alert&#40;1&#41;&quot;',
    js: '\\x27\\x20onload\\x3D\\x22alert\\x281\\x29\\x22',
    jsAttr: '&#92;x27&#92;x20onload&#92;x3D&#92;x22alert&#92;x281&#92;x29&#92;x22',
    uri: '%27%20onload%3D%22alert%281%29%22',
    css: '\\27 \\20 onload\\3d \\22 alert\\28 1\\29 \\22 ',
    style: '&#92;27 &#92;20 onload&#92;3d &#92;22 alert&#92;28 1&#92;29 &#92;22 '
  },
  {
    input: '<ha>, \'ha\', "ha"',
    html: '&lt;ha&gt;, &#39;ha&#39;, &quot;ha&quot;',
    js: '\\x3Cha\\x3E,\\x20\\x27ha\\x27,\\x20\\x22ha\\x22',
    jsAttr: '&#92;x3Cha&#92;x3E,&#92;x20&#92;x27ha&#92;x27,&#92;x20&#92;x22ha&#92;x22',
    uri: '%3Cha%3E%2C%20%27ha%27%2C%20%22ha%22',
    css: '\\3c ha\\3e \\2c \\20 \\27 ha\\27 \\2c \\20 \\22 ha\\22 ',
    style: '&#92;3c ha&#92;3e &#92;2c &#92;20 &#92;27 ha&#92;27 &#92;2c &#92;20 &#92;22 ha&#92;22 '
  },
  {
    label: "ESAPI bad JS chars",
    input: "!@$%()=+{}[]",
    html: "&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#x7B;&#x7D;&#91;&#93;",
    js: "\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D",
    jsAttr: "&#92;x21&#92;x40&#92;x24&#92;x25&#92;x28&#92;x29&#92;x3D&#92;x2B&#92;x7B&#92;x7D&#92;x5B&#92;x5D",
    uri: "%21%40%24%25%28%29%3D%2B%7B%7D%5B%5D",
    css: '\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ',
    style: '&#92;21 &#92;40 &#92;24 &#92;25 &#92;28 &#92;29 &#92;3d &#92;2b &#92;7b &#92;7d &#92;5b &#92;5d '
  },
  {
    label: "ESAPI maybe bad chars",
    input: " ,.-_ ",
    html: " ,.-_ ",
    js: "\\x20,.-_\\x20",
    jsAttr: "&#92;x20,.-_&#92;x20",
    uri: "%20%2C.-_%20",
    css: '\\20 \\2c \\2e \\2d \\5f \\20 ',
    style: '&#92;20 &#92;2c &#92;2e &#92;2d &#92;5f &#92;20 '
  },
  {
    label: "ASCII punctuation",
    input: '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~', // punctuation in ASCII range (lexical order)
    html: '&#33;&quot;&#35;&#36;&#37;&amp;&#39;&#40;&#41;&#42;&#43;,-.&#47;&#58;&#59;&lt;&#61;&gt;&#63;&#64;&#91;&#92;&#93;&#94;_&#96;&#x7B;&#x7C;&#x7D;&#x7E;',
    js: '\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2A\\x2B,-.\\x2F\\x3A\\x3B\\x3C\\x3D\\x3E\\x3F\\x40\\x5B\\x5C\\x5D\\x5E_\\x60\\x7B\\x7C\\x7D\\x7E',
    jsAttr: '&#92;x21&#92;x22&#92;x23&#92;x24&#92;x25&#92;x26&#92;x27&#92;x28&#92;x29&#92;x2A&#92;x2B,-.&#92;x2F&#92;x3A&#92;x3B&#92;x3C&#92;x3D&#92;x3E&#92;x3F&#92;x40&#92;x5B&#92;x5C&#92;x5D&#92;x5E_&#92;x60&#92;x7B&#92;x7C&#92;x7D&#92;x7E',
    uri: '%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D%7E',
    css: '\\21 \\22 \\23 \\24 \\25 \\26 \\27 \\28 \\29 \\2a \\2b \\2c \\2d \\2e \\2f \\3a \\3b \\3c \\3d \\3e \\3f \\40 \\5b \\5c \\5d \\5e \\5f \\60 \\7b \\7c \\7d \\7e ',
    style: '&#92;21 &#92;22 &#92;23 &#92;24 &#92;25 &#92;26 &#92;27 &#92;28 &#92;29 &#92;2a &#92;2b &#92;2c &#92;2d &#92;2e &#92;2f &#92;3a &#92;3b &#92;3c &#92;3d &#92;3e &#92;3f &#92;40 &#92;5b &#92;5c &#92;5d &#92;5e &#92;5f &#92;60 &#92;7b &#92;7c &#92;7d &#92;7e '
  },
  {
    label: 'every ASCII char',
    input: ASCII,
    html:
      '         \t\n  \r  '+ // most controls -> space (including NUL)
      '                '+ // 0x10 to 0x1F -> space
      ' ' + // space preserved
      '&#33;&quot;&#35;&#36;&#37;&amp;&#39;&#40;&#41;&#42;&#43;'+
      ',-.'+ // safe punctuation
      '&#47;'+
      '0123456789'+ // in alphanum
      '&#58;&#59;&lt;&#61;&gt;&#63;&#64;'+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ // in alphanum
      '&#91;&#92;&#93;&#94;'+
      '_'+ // safe punctuation
      '&#96;'+
      'abcdefghijklmnopqrstuvwxyz'+ // in alphanum
      '&#x7B;&#x7C;&#x7D;&#x7E;'+
      ' ', // 0x7f -> space
    js:
      '\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0A\\x0B\\x0C\\x0D\\x0E\\x0F\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1A\\x1B\\x1C\\x1D\\x1E\\x1F\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2A\\x2B'+
      ',-.'+ // safe punctuation
      '\\x2F'+
      '0123456789'+ // in alphanum
      '\\x3A\\x3B\\x3C\\x3D\\x3E\\x3F\\x40'+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ // in alphanum
      '\\x5B\\x5C\\x5D\\x5E'+
      '_'+ // safe punctuation
      '\\x60'+
      'abcdefghijklmnopqrstuvwxyz'+ // in alphanum
      '\\x7B\\x7C\\x7D\\x7E\\x7F',
    jsAttr:
      '&#92;x00&#92;x01&#92;x02&#92;x03&#92;x04&#92;x05&#92;x06&#92;x07&#92;x08&#92;x09&#92;x0A&#92;x0B&#92;x0C&#92;x0D&#92;x0E&#92;x0F&#92;x10&#92;x11&#92;x12&#92;x13&#92;x14&#92;x15&#92;x16&#92;x17&#92;x18&#92;x19&#92;x1A&#92;x1B&#92;x1C&#92;x1D&#92;x1E&#92;x1F&#92;x20&#92;x21&#92;x22&#92;x23&#92;x24&#92;x25&#92;x26&#92;x27&#92;x28&#92;x29&#92;x2A&#92;x2B'+
      ',-.'+
      '&#92;x2F'+
      '0123456789'+
      '&#92;x3A&#92;x3B&#92;x3C&#92;x3D&#92;x3E&#92;x3F&#92;x40'+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+
      '&#92;x5B&#92;x5C&#92;x5D&#92;x5E'+
      '_'+
      '&#92;x60'+
      'abcdefghijklmnopqrstuvwxyz'+
      '&#92;x7B&#92;x7C&#92;x7D&#92;x7E&#92;x7F',
    uri: '%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%20%21%22%23%24%25%26%27%28%29%2A%2B%2C'+
      '-.'+ // uri-safe punctuation
      '%2F'+
      '0123456789'+ // in alphanum
      '%3A%3B%3C%3D%3E%3F%40'+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ // in alphanum
      '%5B%5C%5D%5E'+
      '_'+ // uri-safe punctuation
      '%60'+
      'abcdefghijklmnopqrstuvwxyz'+ // in alphanum
      '%7B%7C%7D%7E%7F',
    css: '\\fffd '+ // undefined behaviour
      '\\1 \\2 \\3 \\4 \\5 \\6 \\7 \\8 \\9 \\a \\b \\c \\d \\e \\f \\10 \\11 \\12 \\13 \\14 \\15 \\16 \\17 \\18 \\19 \\1a \\1b \\1c \\1d \\1e \\1f \\20 \\21 \\22 \\23 \\24 \\25 \\26 \\27 \\28 \\29 \\2a \\2b \\2c \\2d \\2e \\2f '+
      '0123456789'+ // alphanum
      '\\3a \\3b \\3c \\3d \\3e \\3f \\40 '+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ // alphanum
      '\\5b \\5c \\5d \\5e \\5f \\60 '+
      'abcdefghijklmnopqrstuvwxyz'+ // alphanum
      '\\7b \\7c \\7d \\7e \\7f ',
    style: '&#92;fffd '+ // undefined behaviour
      '&#92;1 &#92;2 &#92;3 &#92;4 &#92;5 &#92;6 &#92;7 &#92;8 &#92;9 &#92;a &#92;b &#92;c &#92;d &#92;e &#92;f &#92;10 &#92;11 &#92;12 &#92;13 &#92;14 &#92;15 &#92;16 &#92;17 &#92;18 &#92;19 &#92;1a &#92;1b &#92;1c &#92;1d &#92;1e &#92;1f &#92;20 &#92;21 &#92;22 &#92;23 &#92;24 &#92;25 &#92;26 &#92;27 &#92;28 &#92;29 &#92;2a &#92;2b &#92;2c &#92;2d &#92;2e &#92;2f '+
      '0123456789'+ // alphanum
      '&#92;3a &#92;3b &#92;3c &#92;3d &#92;3e &#92;3f &#92;40 '+
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ // alphanum
      '&#92;5b &#92;5c &#92;5d &#92;5e &#92;5f &#92;60 '+
      'abcdefghijklmnopqrstuvwxyz'+ // alphanum
      '&#92;7b &#92;7c &#92;7d &#92;7e &#92;7f '
  },
  {
    label: "URI-encoded input",
    input: '%3Cscript%3E', // i.e., already uri-encoded
    html: '&#37;3Cscript&#37;3E',
    js: '\\x253Cscript\\x253E',
    jsAttr: '&#92;x253Cscript&#92;x253E',
    uri: '%253Cscript%253E',
    css: '\\25 3Cscript\\25 3E',
    style: '&#92;25 3Cscript&#92;25 3E'
  },
  {
    input: "é, ß, "+SNOWMAN+", "+FACE_WITHOUT_MOUTH,
    html: "é, ß, "+SNOWMAN+", "+FACE_WITHOUT_MOUTH,
    js: "\\u00E9,\\x20\\u00DF,\\x20\\u2603,\\x20\\uD83D\\uDE36",
    jsAttr: "&#92;u00E9,&#92;x20&#92;u00DF,&#92;x20&#92;u2603,&#92;x20&#92;uD83D&#92;uDE36",
    uri: '%C3%A9%2C%20%C3%9F%2C%20%E2%98%83%2C%20%F0%9F%98%B6',
    css: '\\e9 \\2c \\20 \\df \\2c \\20 \\2603 \\2c \\20 '+FACE_WITHOUT_MOUTH, // U+10000 and up are preserved
    style: '&#92;e9 &#92;2c &#92;20 &#92;df &#92;2c &#92;20 &#92;2603 &#92;2c &#92;20 '+FACE_WITHOUT_MOUTH
  },
  {
    label: 'CDATA',
    input: '<![CDATA[ blah ]]>',
    html: '&lt;&#33;&#91;CDATA&#91; blah &#93;&#93;&gt;',
    js: '\\x3C\\x21\\x5BCDATA\\x5B\\x20blah\\x20\\x5D\\x5D\\x3E',
    jsAttr: '&#92;x3C&#92;x21&#92;x5BCDATA&#92;x5B&#92;x20blah&#92;x20&#92;x5D&#92;x5D&#92;x3E',
    uri: '%3C%21%5BCDATA%5B%20blah%20%5D%5D%3E',
    css: '\\3c \\21 \\5b CDATA\\5b \\20 blah\\20 \\5d \\5d \\3e ',
    style: '&#92;3c &#92;21 &#92;5b CDATA&#92;5b &#92;20 blah&#92;20 &#92;5d &#92;5d &#92;3e '
  },
  {
    label: 'nbsp',
    input: '\u00A0',
    html: '\u00A0', // un-encoded
    js: '\\u00A0',
    jsAttr: '&#92;u00A0',
    uri: '%C2%A0',
    css: '\\a0 ',
    style: '&#92;a0 '
  },
  {
    label: 'README html example',
    input: '"><script>alert(\'pwn\')</script>',
    html: '&quot;&gt;&lt;script&gt;alert&#40;&#39;pwn&#39;&#41;&lt;&#47;script&gt;'
  },
  {
    label: 'README html example 2',
    input: "x' onerror='alert(1)",
    html: 'x&#39; onerror&#61;&#39;alert&#40;1&#41;'
  },

  {
    label: 'integer literal',
    input: 1234,
    html: "1234",
    js: "1234",
    jsAttr: "1234",
    uri: "1234",
    jsObj: "1234",
    css: "1234",
    style: "1234"
  },
  {
    label: 'boolean literal',
    input: true,
    html: "true",
    js: "true",
    jsAttr: "true",
    uri: "true",
    jsObj: "true",
    css: "true",
    style: "true"
  },
  {
    label: 'float literal',
    input: 1234.5678,
    html: "1234.5678",
    js: "1234.5678",
    jsAttr: "1234.5678",
    uri: "1234.5678",
    jsObj: "1234.5678",
    css: "1234\\2e 5678",
    style: "1234&#92;2e 5678"
  },

  {
    label: 'object literal',
    input: {key:"</script><script>alert(\"hah!\")"},
    jsObj: '{"key":"\\x3C\\x2Fscript\\x3E\\x3Cscript\\x3Ealert\\x28\\"hah\\x21\\"\\x29"}'
  },
  {
    label: 'object literal w/ unicode',
    input: {key:"snowman:"+SNOWMAN},
    jsObj: '{"key":"snowman:\\u2603"}'
  },
  {
    label: 'object w/ LINE SEPARATOR U+2028 and PARAGRAPH SEPARATOR U+2029',
    input: {"line\u2028sep":"para\u2029sep"},
    jsObj: '{"line\\u2028sep":"para\\u2029sep"}'
  },
  {
    label: 'array literal',
    input: [1,2.3,"ouch",'</script><script>alert(\"hah!\")'],
    jsObj: '[1,2.3,"ouch","\\x3C\\x2Fscript\\x3E\\x3Cscript\\x3Ealert\\x28\\"hah\\x21\\"\\x29"]'
  },
  {
    label: 'CDATA in object',
    input: {"open":"<![CDATA[", "close": "]]>"},
    jsObj: '{"open":"\\x3C\\x21[CDATA[","close":"\\x5D\\x5D\\x3E"}'
  },
  {
    label: "nested array doesn't trigger CDATA protection",
    input: [[['a']],['b']],
    jsObj: '[[["a"]],["b"]]'
  }
];


describe('secure filters', function() {
  _.each(ALL_CASES, function(c) {
    var input = c.input;
    var label = c.label || 'input "'+c.input+'"';
    describe('for '+label, function() {
      _.each(c, function(expect, filterName) {
        if (filterName === 'input' || filterName === 'label') {
          return;
        }

        var func = secureFilters[filterName];
        assert(func);
        assert.strictEqual(typeof func, "function");
        it('filter '+filterName+' produces "'+expect+'"', function() {
          var output = func(input);
          assert.strictEqual(output, expect);
        });
      });
    });
  });
});

describe('exporting to EJS', function() {
  function checkAllFilters(ejs) {
    assert(ejs.filters);
    assert(ejs.filters instanceof Object);
    var keys = _.keys(ejs.filters);
    assert.equal(keys.length, 7);
    assert('html' in ejs.filters);
    assert('js' in ejs.filters);
    assert('jsAttr' in ejs.filters);
    assert('uri' in ejs.filters);
    assert('jsObj' in ejs.filters);
    assert('css' in ejs.filters);
    assert('style' in ejs.filters);
  }

  it('.configure()s an empty object', function() {
    var mockEjs = {};
    secureFilters.configure(mockEjs);
    checkAllFilters(mockEjs);
  });
  it('.configure()s an object with .filters', function() {
    var mockEjs = { filters: {} };
    secureFilters.configure(mockEjs);
    checkAllFilters(mockEjs);
  });
});

}(this));
