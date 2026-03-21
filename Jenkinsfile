@Library('swarm-build@master') _

carwashSwarmDeploy(
  targetEnv: defineTargetEnv(),
  imageName: 'carwash-saas-stripe-terminal',
  serviceName: 'carwash_stripe_terminal',
  project: 'carwash',
  contextPath: '.'
)

def defineTargetEnv() {
  def branchName = env.BRANCH_NAME ?: 'unknown'
  echo "BRANCH_NAME: ${env.BRANCH_NAME}"
  
  switch(branchName) {
    case 'master':
      return 'prod'
    default:
      return 'none'
  }
}
