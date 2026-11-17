'use strict';

const { analyze } = require('./src/analyzer');
const { resolveRef } = require('./src/ref');
const security = require('./src/security');
const sensitivity = require('./src/sensitivity');

module.exports = { analyze, resolveRef, security, sensitivity };
