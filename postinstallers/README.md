## Additional postinstall samples, simply update emit_minion/master as needed

A few premade postinstallers you can drop in.

**in-tune_for_linux.sh**
  WIP to deliver linux desktops to darksites with automatci SCCM registration and policy push
  simply configure once, clone hundreds of desktops with a single button.

**unity_game_server.sh**
  Compiles and deploys a prebuilt UNITY server that includes everything you need to run a Unity
  headless server, On first boot.  Perfect for templates and "cattle-like" point and shoot game servers.

**aws**
  deploys free-tier micro vms, requires the awscli tool to b econfigured

**semaphore**
  installs the popular gui ansible tool-kit

**cloud_init-desktop**
  combination, installer and clone tool for mass deployments of remote access (xrdp) desktops
