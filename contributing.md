# Contribution Guide

If you'd like to contribute to or modify secure-filters, here's a quick guide
to get you started.

## Development Dependencies

- [node.js](http://nodejs.org) >= 0.10

## Set-Up

Download via GitHub and install npm dependencies:

```sh
git clone git@github.com:salesforce/secure-filters.git
cd secure-filters

npm install
```

## Testing

Testing is with the [mocha](https://github.com/visionmedia/mocha) framework.
Tests are located in the `tests/` directory.

The unit tests are run twice: once under node.js and once under
[PhantomJS](http://phantomjs.org/). PhantomJS test files are located in the
`static/` directory.

To run the tests:

```sh
npm test
```

## Publishing

1. `npm version patch` (increments `x` in `z.y.x`, then makes a commit for package.json, tags that commit)
2. `git push --tags origin master`
3. `npm publish`

Go to https://npmjs.org/package/secure-filters and verify it published (can take several minutes)

## Contributor License Agreement (CLA)

Contributions to Salesforce.com open-source projects currently requires a CLA.
Please contact one of the project maintainers to get a copy.

