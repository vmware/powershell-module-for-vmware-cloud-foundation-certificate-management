# Get-EsxiHostVsanMaintenanceModePrecheck

## Synopsis

Checks for any issues when the ESXi host enters a particular vSAN maintenance mode.

## Syntax

```powershell
Get-EsxiHostVsanMaintenanceModePrecheck [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [[-esxiFqdn] <String>] [-vsanDataMigrationMode] <String> [<CommonParameters>]
```

## Description

The `Get-EsxiHostVsanMaintenanceModePrecheck` cmdlet checks if there's any issue for the ESXi host entering a particular vSAN maintenance mode. The cmdlet will halt the script if the pre-check fails.

If `esxiFqdn` is provided, only the value for that host is returned.

## Examples

### Example 1

```powershell
Get-EsxiHostVsanMaintenanceModePrecheck -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMware1! -domain sfo-m01 -cluster sfo-m01-cl01 -vsanDataMigrationMode Full
```

This example checks each ESXi host within a cluster within the workload domain for any issues when entering maintenance mode with vSAN maintenance mode set to Full migration

### Example 2

```powershell
Get-EsxiHostVsanMaintenanceModePrecheck -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMware1! -domain sfo-m01 -host sfo01-m01-esx01.sfo.rainpole.io -vsanDataMigrationMode Full
```

This example checks the ESXi host within the workload domain for any issues when entering maintenance mode with vSAN maintenance mode set to Full migration

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

The name of the cluster in which the ESXi host is located.

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

The fully qualified domain name of the ESXi host within the workload domain.

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

### -vsanDataMigrationMode

The vSan Data Migration mode validate value ("Full", "EnsureAccessibility", "NoDataMigration").

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
