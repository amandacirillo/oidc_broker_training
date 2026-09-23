#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { OidcBrokerStack } from '../lib/oidc_broker_stack.js';

const app = new cdk.App();

// All placeholders - replace with your own sandbox account's VPC and an ACM certificate ARN
// before running `cdk synth` for real (see cdk/README section in the repo README).
new OidcBrokerStack(app, 'OidcBrokerTrainingStack', {
  vpcId: 'vpc-EXAMPLE00SANDBOX1',
  certificateArn: 'arn:aws:acm:us-east-1:111111111111:certificate/EXAMPLE-CERT-ID',
  env: {
    account: '111111111111',
    region: 'us-east-1',
  },
});
