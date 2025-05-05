# Get-EsxiLockdownMode

## Synopsis

Retrieves the ESX host lockdown mode state from a vCenter instance.

## Syntax

```powershell
Get-EsxiLockdownMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [[-esxiFqdn] <String>] [<CommonParameters>]
```

## Description

The `Get-EsxiLockdownMode` cmdlet gets the lockdown mode value for all ESX hosts in a given cluster or for a given ESX host within the cluster.

If `esxiFqdn` is provided, only the value for that host is returned.

## Examples

### Example 1

```powershell
Get-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name]
```

This example retrieves the lockdown mode for each ESX host in a cluster.

### Example 2

```powershell
Get-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -esxiFqdn [esx_host_fqdn]
```

This example retrieves the lockdown mode state for an ESX host in a given cluster.

## Parameters

### -server

The fully qualified domain name of the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -user

The username to authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -pass

The passwordto authenticate to the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -domain

The name of the workload domain in which the cluster is located.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -cluster

The name of the cluster in which the ESX host is located.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The fully qualified domain name of the ESX host to retrieve the lockdown mode state for.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
