# CS-Intern
A professional-grade cybersecurity lab environment with VM setups, network configurations, and tools for hands-on training in threat detection, penetration testing, and incident response.

# Lab Environment Preparation
 Set up and validate the host system to ensure it meets the minimum technical requirements for running virtualized lab environments. The following prerequisites must be fulfilled:
 
*)VirtualBox (Primary virtualization platform)
*) VMware Workstation Player (Optional, as an alternative or secondary platform)

*)Task Start date: 05-21-2025

*)Task End Date: 06-02-2025

# 1. Executive Summary
This report outlines the design and implementation of a comprehensive cybersecurity lab environment to simulate real-world offensive and defensive security operations. Utilizing a multi-virtual machine (VM) architecture, the lab enables hands-on experience in vulnerability assessment, penetration testing, threat detection, and incident response.

The lab incorporates the following components:

*) Kali Linux as the attacker machine

*) Metasploitable2 as the vulnerable target

*) Security Onion as the monitoring and alerting system

*) pfSense as the firewall and gateway

*) Ubuntu Server as an optional internal host

 Primary Objectives:

Build a controlled cybersecurity training lab

Develop practical skills in offensive and defensive security

Conduct vulnerability assessments and penetration testing

Deploy and analyze SIEM tools for monitoring and alerting

# 2. Lab Architecture & Network Topology

#2.1 Virtualization Platform
Hypervisor: Oracle VirtualBox (cross-platform compatibility)

Networking Configuration:

Adapter 1: NAT (Internet access)

Adapter 2: Host-Only (internal isolated network)

#2.2 Virtual Machines Configuration

VM Name       Purpose        Network Configuration        Key Tools
------------------------------------------------------------------- 
   ![alt text](image-1.png)  

   -----------------------------------------------------------------

   #  Step-by-Step Implementation
     3.1 pfSense Firewall Configuration 
     
  Installation
1. Downloaded the latest pfSense Community Edition ISO from the official website.
2. Created a new VM in VirtualBox with:
 *)GB RAM, 2 CPUs, 20 GB storage.
 *)Two network adapters:
     i)Adapter 1: NAT (for internet access).
     ii)Adapter 2: Host-Only (for internal LAN).
3. Booted the VM, followed the pfSense installer prompts, and completed the setup.   