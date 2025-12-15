## Ansible cluster installer

cd /srv/ansible
export ANSIBLE_CONFIG=/srv/ansible/ansible.cfg

ansible-playbook playbooks/00_preflight.yml
ansible-playbook playbooks/01_common.yml
ansible-playbook playbooks/02_containerd.yml
ansible-playbook playbooks/03_k8s_packages.yml
ansible-playbook playbooks/04_lb.yml
ansible-playbook playbooks/05_cp_init.yml
ansible-playbook playbooks/06_cp_join.yml
ansible-playbook playbooks/07_worker_join.yml
ansible-playbook playbooks/08_cilium.yml
ansible-playbook playbooks/09_ingress.yml
ansible-playbook playbooks/10_monitoring.yml
ansible-playbook playbooks/99_verify.yml
