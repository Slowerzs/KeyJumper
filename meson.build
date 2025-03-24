project('Jumper', 'c',
  version : '0.1',
  default_options : ['warning_level=3', 'c_std=c23'],
  )

includes_launcher = 'include/'

subdir('src')


executable(
  'launcher',
  'src/launcher/main.c',
  include_directories: includes_launcher,
  link_with: [launcher_lib, utils_lib, jop_lib]
)