import test from 'node:test';
import assert from 'node:assert/strict';
import {validateTarget,hostnameSlug} from '../server/security.js';
test('allows public IPv4 target',()=>assert.deepEqual(validateTarget('8.8.8.8',3000),{host:'8.8.8.8',port:3000}));
test('blocks private, loopback, link-local and documentation ranges',()=>{for(const h of ['127.0.0.1','10.0.0.1','192.168.1.2','169.254.1.2','203.0.113.5','198.51.100.9'])assert.throws(()=>validateTarget(h,3000));});
test('blocks hostnames and risky ports',()=>{assert.throws(()=>validateTarget('localhost',3000));assert.throws(()=>validateTarget('8.8.8.8',22));});
test('matches one-level subdomains',()=>{assert.equal(hostnameSlug('a1.example.com','example.com'),'a1');assert.equal(hostnameSlug('a.b.example.com','example.com'),null);});
