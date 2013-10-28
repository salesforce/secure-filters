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

'use strict';
var assert = require('assert');

var secureFilters = require('./index');

// Test character outside of the unicode BMP:
var FACE_WITHOUT_MOUTH = "\uD83D\uDE36"; // U+1F636, UTF-8: F0 9F 98 B6

var ALL_CASES = [
  {
    input: '&&amp;\'d',
    html: '&amp;&amp;&#39;d',
    js: '&&amp;\\\'d',
    jsAttr: '&amp;&amp;\\&#39;d',
    uri: '%26%26amp%3B%27d',
  },
  {
    input: '\' onload="alert(1)"',
    html: '&#39; onload=&quot;alert(1)&quot;',
    js: '\\\' onload=\\"alert(1)\\"',
    jsAttr: '\\&#39; onload=\\&quot;alert(1)\\&quot;',
    uri: '%27%20onload%3D%22alert%281%29%22',
  },
  {
    input: '<ha>, \'ha\', "ha"',
    html: '&lt;ha&gt;, &#39;ha&#39;, &quot;ha&quot;',
    js: '\\u003Cha\\u003E, \\\'ha\\\', \\"ha\\"',
    jsAttr: '&lt;ha&gt;, \\&#39;ha\\&#39;, \\&quot;ha\\&quot;',
    uri: '%3Cha%3E%2C%20%27ha%27%2C%20%22ha%22',
  },
  {
    input: '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~', // punctuation in ASCII range (byte order)
    html: '!&quot;#$%&amp;&#39;()*+,-./:;&lt;=&gt;?@[\\]^_`{|}~',
    js: '!\\"#$%&\\\'()\\*+,-./:;\\u003C=\\u003E?@[\\\\]^_`{|}~',
    jsAttr: '!\\&quot;#$%&amp;\\&#39;()\\*+,-./:;&lt;=&gt;?@[\\\\]^_`{|}~',
    uri: '%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D%7E',
  },
  {
    input: '%3Cscript%3E', // i.e., already uri-encoded
    html: '%3Cscript%3E',
    js: '%3Cscript%3E',
    jsAttr: '%3Cscript%3E',
    uri: '%253Cscript%253E',
  },
  {
    input: "é,ß,&☃ "+FACE_WITHOUT_MOUTH,
    html: "é,ß,&amp;☃ "+FACE_WITHOUT_MOUTH,
    js: "é,ß,&☃ "+FACE_WITHOUT_MOUTH,
    jsAttr: "é,ß,&amp;☃ "+FACE_WITHOUT_MOUTH,
    uri: '%C3%A9%2C%C3%9F%2C%26%E2%98%83%20%F0%9F%98%B6',
  },
  {
    label: 'control characters',
    input: '\u0000,\u0001,\u0002...\u001F',
    uri: '%00%2C%01%2C%02...%1F',
  },

  {
    label: 'integer literal',
    input: 1234,
    html: "1234",
    js: "1234",
    jsAttr: "1234",
    uri: "1234",
    jsObj: "1234"
  },
  {
    label: 'boolean literal',
    input: true,
    html: "true",
    js: "true",
    jsAttr: "true",
    uri: "true",
    jsObj: "true"
  },
  {
    label: 'float literal',
    input: 1234.5678,
    html: "1234.5678",
    js: "1234.5678",
    jsAttr: "1234.5678",
    uri: "1234.5678",
    jsObj: "1234.5678"
  },
  {
    label: 'object literal',
    input: {key:"</script><script>alert(\"hah!\")"},
    jsObj: '{"key":"\\u003C/script\\u003E\\u003Cscript\\u003Ealert(\\"hah!\\")"}'
  },
  {
    label: 'array literal',
    input: [1,2.3,"ouch",'</script><script>alert(\"hah!\")'],
    jsObj: '[1,2.3,"ouch","\\u003C/script\\u003E\\u003Cscript\\u003Ealert(\\"hah!\\")"]'
  }
];

describe('secure filters', function() {
  ALL_CASES.forEach(function(c) {
    var input = c.input;
    var label = c.label || 'input "'+c.input+'"';
    describe('for '+label, function() {
      Object.keys(c).forEach(function(filterName) {
        if (filterName === 'input' || filterName === 'label') {
          return;
        }

        var func = secureFilters[filterName];
        assert(func);
        assert.strictEqual(typeof func, "function");
        var expect = c[filterName];
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
    var keys = Object.keys(ejs.filters);
    assert.equal(keys.length, 4);
    assert('html' in ejs.filters);
    assert('js' in ejs.filters);
    assert('jsAttr' in ejs.filters);
    assert('uri' in ejs.filters);
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
