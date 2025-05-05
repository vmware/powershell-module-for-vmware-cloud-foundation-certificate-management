# Set-EsxiLockdownMode

## Synopsis

Sets the lockdown mode for all ESX hosts in a given cluster.

## Syntax

### enable

```powershell
Set-EsxiLockdownMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-enable] [<CommonParameters>]
```

### disable

```powershell
Set-EsxiLockdownMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String>
 [-disable] [<CommonParameters>]
```

## Description

The `Set-EsxiLockdownMode` cmdlet sets the lockdown mode for all ESX hosts in a given cluster.

## Examples

### Example 1

```powershell
Set-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -enable
```

This example will enable the lockdown mode for all ESX hosts in a cluster.

### Example 2

```powershell
Set-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -disable
```

This example will disable the lockdown mode for all ESX hosts in a cluster.

## Parameters

### -server

The fully qualified domain name of the SDDC Manager instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Position: Named
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
Position: Named
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
Position: Named
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
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -enable

Enable lockdown mode for the ESX host(s).

```yaml
Type: SwitchParameter
Parameter Sets: enable
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -disable

Disable lockdown mode for the ESX host(s).

```yaml
Type: SwitchParameter
Parameter Sets: disable
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: `-Debug`, `-ErrorAction`, `-ErrorVariable`, `-InformationAction`, `-InformationVariable`, `-OutVariable`, `-OutBuffer`, `-PipelineVariable`, `-Verbose`, `-WarningAction`, and `-WarningVariable`. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).