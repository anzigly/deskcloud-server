#!/usr/bin/env python

#TODO:Load configure from a conf file!

import os
def shutdown_iptables():
	os.system('service iptables stop')
	os.system('chkconfig iptables off')

def chk_yum_installed(package_name):
	re = os.system('yum list installed | grep %s'%package_name)
	if re == 0:
		return True
	else:
		return False
def yum_install(package_name):
	os.system('yum install -y %s'%package_name)

def chk_install(package_name):
	if not chk_yum_installed(package_name):
		yum_install(package_name)

def solve_dependencies():
	packages = ['spice-server', 'spice-gtk-tools', 'python-crypto', 'ImageMagick', 'redis', 'python-redis', 'openssh-askpass']
	for package in packages:
		chk_install(package)

def chk_install_rsa():
	try:
		import rsa
	except:
		if not chk_python_module('rsa'):
			os.system('easy_install rsa')

def deploy_hook():
	hook_dir = '/etc/libvirt/hooks'
	hook_file = '%s/qemu'%hook_dir
	if not os.path.isdir(hook_dir):
		os.mkdir(hook_dir)
	if os.path.isfile(hook_file):
		os.remove(hook_file)
	os.link('qemu', hook_file)

if __name__ == '__main__':
	shutdown_iptables()
	solve_dependencies()
	chk_install_rsa()
	deploy_hook()
