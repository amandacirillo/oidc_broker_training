import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as elbv2_actions from 'aws-cdk-lib/aws-elasticloadbalancingv2-actions';
import * as cognito from 'aws-cdk-lib/aws-cognito';

/**
 * The infrastructure half of this training: two Application Load Balancers in front of one ECS
 * service, wired the way broker-provider's real stack is - because that split is the part of
 * this pattern that is easiest to get wrong, and a CDK stack is where you'd actually declare it.
 *
 * All IDs below (VPC, hosted zone, certificate ARN, Cognito pool) are placeholders. This stack is
 * meant to be read and `cdk synth`'d against your own sandbox account, not deployed as-is.
 */
export interface OidcBrokerStackProps extends cdk.StackProps {
  vpcId: string;
  certificateArn: string;
}

export class OidcBrokerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: OidcBrokerStackProps) {
    super(scope, id, props);

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: props.vpcId });

    const cluster = new ecs.Cluster(this, 'Cluster', { vpc });

    const taskDefinition = new ecs.FargateTaskDefinition(this, 'BrokerTaskDef', {
      cpu: 256,
      memoryLimitMiB: 512,
    });
    taskDefinition.addContainer('broker', {
      image: ecs.ContainerImage.fromRegistry('public.ecr.aws/docker/library/node:20-alpine'),
      portMappings: [{ containerPort: 3000 }],
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: 'oidc-broker' }),
    });

    const service = new ecs.FargateService(this, 'BrokerService', {
      cluster,
      taskDefinition,
      desiredCount: 2,
    });

    // --- Public / browser-facing ALB ---
    // Fronts the browser-visible parts of the flow: /authorize and /interaction/*. This is the
    // ALB with the authenticate-oidc listener action - Entra (or whichever IdP) sits behind it.
    const publicAlb = new elbv2.ApplicationLoadBalancer(this, 'PublicAlb', {
      vpc,
      internetFacing: true,
    });

    const publicListener = publicAlb.addListener('PublicHttpsListener', {
      port: 443,
      certificates: [{ certificateArn: props.certificateArn }],
      defaultAction: elbv2.ListenerAction.fixedResponse(404, { messageBody: 'not found' }),
    });

    const brokerTargetGroup = publicListener.addTargets('BrokerTargets', {
      port: 3000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [service],
      healthCheck: { path: '/healthz' },
    });

    // A placeholder user pool standing in for the real IdP integration (Entra, in the source
    // project) - ALB's authenticate-oidc action needs *an* OIDC IdP to talk to, and Cognito lets
    // this stack synth and, if you deploy it into your own sandbox, actually exercise a real
    // authenticate-oidc redirect without needing your org's tenant.
    const userPool = new cognito.UserPool(this, 'DemoIdpPool');
    const userPoolClient = new cognito.UserPoolClient(this, 'DemoIdpClient', { userPool });
    const userPoolDomain = userPool.addDomain('DemoIdpDomain', {
      cognitoDomain: { domainPrefix: 'oidc-broker-training-example' },
    });

    // Priority matters: the authenticate-oidc rule must be a LOWER number (higher priority) than
    // the catch-all rule below, or ALB never reaches it and every request skips the IdP entirely.
    publicListener.addAction('AuthenticatedBrowserPaths', {
      priority: 10,
      conditions: [elbv2.ListenerCondition.pathPatterns(['/authorize', '/interaction/*'])],
      action: new elbv2_actions.AuthenticateCognitoAction({
        userPool,
        userPoolClient,
        userPoolDomain,
        next: elbv2.ListenerAction.forward([brokerTargetGroup]),
      }),
    });

    // Second, unauthenticated rule: /jwks, /.well-known/*, /healthz, and anything else the
    // browser or a client library fetches directly, with no IdP round-trip. Getting this rule's
    // priority number WRONG relative to the one above is the single most common way to break this
    // pattern - see the README's "why two ALBs" section for what it looks like when you do.
    publicListener.addAction('UnauthenticatedPublicPaths', {
      priority: 20,
      conditions: [elbv2.ListenerCondition.pathPatterns(['/*'])],
      action: elbv2.ListenerAction.forward([brokerTargetGroup]),
    });

    // --- Internal back-channel ALB ---
    // /token and /me (userinfo) are called by a relying party's own ALB nodes, server-to-server,
    // never by a browser. Routing them through the same internet-facing ALB above works in a demo
    // but fails intermittently in real AWS (AuthTokenEpRequestTimeout) once the calling ALB's node
    // IPs aren't part of the public ALB's expected ingress path - hence a second, internal-only
    // ALB whose traffic never leaves the VPC.
    const internalAlb = new elbv2.ApplicationLoadBalancer(this, 'InternalAlb', {
      vpc,
      internetFacing: false,
    });

    const internalListener = internalAlb.addListener('InternalHttpsListener', {
      port: 443,
      certificates: [{ certificateArn: props.certificateArn }],
      defaultAction: elbv2.ListenerAction.fixedResponse(404, { messageBody: 'not found' }),
    });

    internalListener.addAction('BackChannelPaths', {
      priority: 10,
      conditions: [elbv2.ListenerCondition.pathPatterns(['/token', '/me'])],
      // No authenticate-oidc action here at all - these calls carry their own client secret /
      // bearer token instead of an ALB-relayed browser identity.
      action: elbv2.ListenerAction.forward([brokerTargetGroup]),
    });

    new cdk.CfnOutput(this, 'PublicAlbDnsName', { value: publicAlb.loadBalancerDnsName });
    new cdk.CfnOutput(this, 'InternalAlbDnsName', { value: internalAlb.loadBalancerDnsName });
  }
}
