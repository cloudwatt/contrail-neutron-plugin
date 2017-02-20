#!groovy
node('dockerHost_int0'){
 //Add job properties
  properties ([[
   $class: 'ParametersDefinitionProperty',
     parameterDefinitions: [
       [$class: 'StringParameterDefinition',
          defaultValue: 'git@git.corp.cloudwatt.com:applications/contrail-neutron-plugin.git',
          description: 'Contrail-neutron-plugin Application git URL',
          name: 'GITURL'],
       [$class: 'StringParameterDefinition',
          defaultValue: 'R2.21-cloudwatt',
          description: 'Contrail Application BranchName/Tag/HashCommit',
          name: 'BRANCH']
  ]],
  [$class: 'jenkins.model.BuildDiscarderProperty',
  strategy: [$class : 'LogRotator', numToKeepStr : '10', daysToKeepStr: '30', artifactNumToKeepStr: '5']]
  ])

  //Clean workspace and clone the default branch setup in the neutron-lbaas repo.
  cloudwatt.init_noshallow()

  withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'e6c78ebc-37b5-43a3-b014-42a575e8c1a0', passwordVariable: 'DEVPI_PASSWORD', usernameVariable: 'DEVPI_USERNAME']]) {
     sh '''docker run --rm \
                    -v $PWD/:/opt/sources/ \
                    -e DEVPI_PASSWORD=$DEVPI_PASSWORD \
                    -e DEVPI_USERNAME=$DEVPI_USERNAME \
                    -e HTTP_PROXY=$HTTP_PROXY \
                    -e HTTPS_PROXY=$HTTP_PROXY \
                    -e PIP_TRUSTED_HOST=$PIP_TRUSTED_HOST \
                    -e PIP_INDEX_URL=$PIP_INDEX_URL \
                     r.cwpriv.net/jenkins/python-builder:14.04-latest'''}
}
