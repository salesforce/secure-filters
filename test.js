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

/* crazy test vectors from http://code.google.com/p/browsersec/wiki/Part1
 * 01: <B <SCRIPT>alert(1)</SCRIPT>>
 * 02: <B="<SCRIPT>alert(1)</SCRIPT>">
 * 03: <IMG SRC=`javascript:alert(1)`>
 * 04: <S[0x00]CRIPT>alert(1)</S[0x00]CRIPT>
 * 05: <A """><IMG SRC="javascript:alert(1)">
 * 06: <IMG onmouseover =alert(1)>
 * 07: <A/HREF="javascript:alert(1)">
 * 08: <!-- Hello -- world > <SCRIPT>alert(1)</SCRIPT> -->
 * 09: <IMG ALT="><SCRIPT>alert(1)</SCRIPT>"(EOF)
 * 10: <![><IMG ALT="]><SCRIPT>alert(1)</SCRIPT>">
 */

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
    input: "é,ß,&☃",
    html: "é,ß,&amp;☃",
    js: "é,ß,&☃",
    jsAttr: "é,ß,&amp;☃",
    uri: '%C3%A9%2C%C3%9F%2C%26%E2%98%83',
  },
  {
    label: 'control characters',
    input: '\u0000,\u0001,\u0002...\u001F',
    uri: '%00%2C%01%2C%02...%1F',
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
        var expect = c[filterName];
        it('filter '+filterName+' produces "'+expect+'"', function() {
          var output = func(input);
          assert.strictEqual(output, expect);
        });
      });
    });
  });
});
