/*!
 * Copyright 2013 GoInstant Inc., a salesforce.com company
 * See LICENSE.txt for details.
 */
(function(root) {
'use strict';

var assert;
var secureFilters;

if (typeof module !== 'undefined' && module.exports) {
  assert = require('gi-assert');
  secureFilters = require('../index');
} else {
  assert = root.assert;
  secureFilters = root.secureFilters;
}

var handlebars;
try {
  handlebars = require('handlebars');
} catch(e) {
  describe('handlebars');
  return;
}

describe('handlebars', function() {
  it('gets configured', function() {
    secureFilters.configureHandlebars(handlebars, true);
  });

  it('can compile a and properly sanitize a fun template', function() {
    var template = handlebars.compile(
      '<script>\n'+
      '  var config = {{jsObj config}};\n'+
      '  var userId = parseInt("{{js userId}}",10);\n'+
      '</script>\n'+
      '<a href="/welcome/{{uri userId}}">'+
        'Welcome {{userName}}</a> (userId {{userId}})\n'+
      '<br>\n'+
      '<a href="javascript:activate(\'{{jsAttr userId}}\')">'+
        'Click here to activate {{html userName}}</a>\n'
    );

    var result = template({
      config: { stuff: [1,'2',false] },
      userId: '\'"&<>`@', // handlebars doesn't escape @
      userName: 'John, Roberts & Smith'
    });

    assert.equal(result,
      '<script>\n'+
      '  var config = {"stuff":[1,"2",false]};\n'+
      '  var userId = parseInt("\\x27\\x22\\x26\\x3C\\x3E\\x60\\x40",10);\n'+
      '</script>\n'+
      '<a href="/welcome/%27%22%26%3C%3E%60%40">'+
        'Welcome John, Roberts &amp; Smith</a> (userId &#39;&quot;&amp;&lt;&gt;&#96;&#64;)\n'+
      '<br>\n'+
      '<a href="javascript:activate(\'&#92;x27&#92;x22&#92;x26&#92;x3C&#92;x3E&#92;x60&#92;x40\')">'+
        'Click here to activate John, Roberts &amp; Smith</a>\n'
    );
  });

});

}(this));
