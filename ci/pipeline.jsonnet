local action = import 'action.libsonnet';
local group = import 'group.libsonnet';
local job = import 'job.libsonnet';
local resource = import 'resource.libsonnet';
local resource_type = import 'resource_type.libsonnet';
local version = import 'version.libsonnet';

local component = 'login-consent';

local source_repo = 'git@github.com:nbycomp/login-consent.git';
local image_repo = 'registry.nearbycomputing.com/nbycomp/core/auth/login-consent';

{
  groups: [
    {
      name: 'develop',
      jobs: [
        'pr',
        'update-pipeline',
        component + '-develop',
      ],
    },
  ] + group.releases(component),

  resource_types: [
    resource_type.pull_request,
  ],

  resources:
    [
      resource.repo_ci_tasks,
      resource.repo_develop(component, source_repo),
      resource.repo_pipeline(source_repo),
      resource.pr('nbycomp/login-consent'),
    ]
    +
    resource.repos_release(component, source_repo) +
    resource.versions_all(component) +
    resource.images_all(component, image_repo),

  jobs:
    [
      job.update_pipeline,
      job.develop_build(component),
      job.pr,
    ] +
    [job.tag_patch(component, r) for r in version.releases] +
    [job.release_build(component, r) for r in version.releases],
}
