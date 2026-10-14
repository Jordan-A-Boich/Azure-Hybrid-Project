// core.bicep - Azure network foundation for the hybrid AG lab
//
// Matches the portal build as of 2026-10-09 (end of session 4, through step 12):
//   - VNet vnet-hyb-westus3 (10.20.0.0/16) with snet-edge, snet-identity, snet-sql
//   - NSGs with the same combined rules built in the portal
//   - nsg-hyb-edge includes the two "forwarded" rules added in step 9
//   - snet-identity and snet-sql have default outbound internet (not private)
//   - VNet DNS: AZ-DC02 (10.20.1.10) first, SQLLab-DC (192.168.100.10) second
//   - Route table sending lab-bound traffic to AZ-WG01 (10.20.0.4)
//   - Witness storage account (existing name passed in as a parameter; cluster uses it as Cloud Witness)
//   - nsg-hyb-sql allow-sql-tcp includes WinRM 5985 (added in step 10 for remote management)
//
// Re-deploying over the existing resources is safe: names, rules and settings match.
// VMs (AZ-WG01, AZ-DC02, AZ-SQL01) are NOT in this file; they were built in the portal.
// AZ-SQL01's NIC reserves 10.20.2.21 (primary), 10.20.2.50 (cluster) and 10.20.2.60 (listener).
//
// Usage:
//   $sa = az storage account list -g rg-hyb-core --query "[0].name" -o tsv
//   az deployment group what-if -g rg-hyb-core -f .\core.bicep -p witnessStorageName=$sa
//   az deployment group create  -g rg-hyb-core -f .\core.bicep -p witnessStorageName=$sa

param location string = resourceGroup().location

@description('Name of the existing witness storage account. Must match exactly, or a second account is created.')
param witnessStorageName string

@description('The lab network on the laptop')
param labPrefix string = '192.168.100.0/24'

@description('The Azure network address range')
param vnetPrefix string = '10.20.0.0/16'

@description('Private IP of AZ-WG01, the Azure end of the WireGuard tunnel')
param wgApplianceIp string = '10.20.0.4'

@description('VNet DNS servers: AZ-DC02 first, SQLLab-DC second')
param dnsServers array = [ '10.20.1.10', '192.168.100.10' ]

@description('Free default outbound internet for snet-identity and snet-sql (portal: "private subnet" unchecked)')
param workloadDefaultOutbound bool = true

@description('Optional NAT gateway for outbound internet instead. Bills hourly while it exists.')
param includeNatGateway bool = false

var tags = { project: 'hybrid-ag-lab' }
var sources = [ labPrefix, vnetPrefix ]
var natGwId = resourceId('Microsoft.Network/natGateways', 'ng-hyb-westus3')

// ---------- Shared deny rule ----------
// Azure's built-in AllowVnetInBound treats the lab as "inside" once routes exist.
// This deny makes the explicit allow rules above it actually restrict traffic.
var denyVnet = {
  name: 'deny-vnet-other'
  properties: {
    priority: 4000
    direction: 'Inbound'
    access: 'Deny'
    protocol: '*'
    sourceAddressPrefix: 'VirtualNetwork'
    sourcePortRange: '*'
    destinationAddressPrefix: '*'
    destinationPortRange: '*'
  }
}

// ---------- nsg-hyb-sql: SQL, AG endpoint, cluster, management ----------
resource nsgSql 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-hyb-sql'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-sql-tcp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          // SQL, AG endpoint, cluster, RPC mapper, SMB, RDP, WinRM (added step 10), RPC dynamic
          destinationPortRanges: [ '1433', '5022', '3343', '135', '445', '3389', '5985', '49152-65535' ]
        }
      }
      {
        name: 'allow-sql-udp'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Udp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3343'
        }
      }
      {
        name: 'allow-icmp'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      denyVnet
    ]
  }
}

// ---------- nsg-hyb-identity: Active Directory and DNS ----------
resource nsgId 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-hyb-identity'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-ad-tcp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          // DNS, Kerberos, RPC mapper, LDAP, SMB, kpasswd, LDAPS, GC, RDP, ADWS, RPC dynamic
          destinationPortRanges: [ '53', '88', '135', '389', '445', '464', '636', '3268-3269', '3389', '9389', '49152-65535' ]
        }
      }
      {
        name: 'allow-ad-udp'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Udp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          // DNS, Kerberos, NTP, LDAP, kpasswd
          destinationPortRanges: [ '53', '88', '123', '389', '464' ]
        }
      }
      {
        name: 'allow-icmp'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefixes: sources
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      denyVnet
    ]
  }
}

// ---------- nsg-hyb-edge: the tunnel VM's subnet ----------
resource nsgEdge 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-hyb-edge'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        // The tunnel's only door from the internet
        name: 'allow-wireguard'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Udp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '51820'
        }
      }
      {
        // Azure-initiated traffic headed to the lab, passing through AZ-WG01 (added in step 9)
        name: 'allow-azure-to-lab-forwarded'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: vnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: labPrefix
          destinationPortRange: '*'
        }
      }
      {
        // Lab traffic leaving AZ-WG01 toward Azure VMs, still carrying 192.168.100.x (added in step 9)
        name: 'allow-lab-to-azure-forwarded'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: labPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: vnetPrefix
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ---------- Route table: lab-bound traffic goes to AZ-WG01 ----------
resource rtLab 'Microsoft.Network/routeTables@2024-05-01' = {
  name: 'rt-hyb-to-lab'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'to-lab'
        properties: {
          addressPrefix: labPrefix
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: wgApplianceIp
        }
      }
    ]
  }
}

// ---------- Optional NAT gateway (not used in the current build) ----------
resource natPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (includeNatGateway) {
  name: 'pip-hyb-natgw'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource natGw 'Microsoft.Network/natGateways@2024-05-01' = if (includeNatGateway) {
  name: 'ng-hyb-westus3'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIpAddresses: [ { id: natPip.id } ]
    idleTimeoutInMinutes: 10
  }
}

var natProp = includeNatGateway ? { natGateway: { id: natGwId } } : {}

// ---------- The virtual network ----------
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-hyb-westus3'
  location: location
  tags: tags
  dependsOn: [ natGw ]
  properties: {
    addressSpace: { addressPrefixes: [ vnetPrefix ] }
    dhcpOptions: { dnsServers: dnsServers }
    subnets: [
      {
        // AZ-WG01 lives here. No route table: it IS the next hop.
        // Private subnet; AZ-WG01 reaches the internet through its own public IP.
        name: 'snet-edge'
        properties: {
          addressPrefix: '10.20.0.0/24'
          networkSecurityGroup: { id: nsgEdge.id }
          defaultOutboundAccess: false
        }
      }
      {
        // AZ-DC02 (10.20.1.10)
        name: 'snet-identity'
        properties: union({
          addressPrefix: '10.20.1.0/24'
          networkSecurityGroup: { id: nsgId.id }
          routeTable: { id: rtLab.id }
          defaultOutboundAccess: workloadDefaultOutbound
        }, natProp)
      }
      {
        // AZ-SQL01 (10.20.2.21; NIC also holds .50 cluster and .60 listener)
        name: 'snet-sql'
        properties: union({
          addressPrefix: '10.20.2.0/24'
          networkSecurityGroup: { id: nsgSql.id }
          routeTable: { id: rtLab.id }
          serviceEndpoints: [ { service: 'Microsoft.Storage' } ]
          defaultOutboundAccess: workloadDefaultOutbound
        }, natProp)
      }
    ]
  }
}

// ---------- Witness storage account (Cloud Witness since step 11, configured with key2) ----------
resource witness 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: witnessStorageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

output witnessAccount string = witness.name
output vnetDns array = dnsServers
