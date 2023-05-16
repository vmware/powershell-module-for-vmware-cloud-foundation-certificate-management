# Set-EsxiConnectionState

## SYNOPSIS

Sets the ESXi host connection state in vCenter Server.

## SYNTAX

```powershell
Set-EsxiConnectionState [-esxiFqdn] <String> [-state] <String> [[-vsanDataMigrationMode] <String>]
 [[-timeout] <String>] [[-pollInterval] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Set-EsxiConnectionState cmdlet sets the connection state of an ESXi host.
One of "Connected", "Disconnected", "Maintenance", or "NotResponding".
If setting the connection state to Maintenance, you must provide the VsanDataMigrationMode.
One of "Full", "EnsureAccessibility", or "NoDataMigration".
Depends on a connection to a vCenter Server instance.

## EXAMPLES

### EXAMPLE 1

```powershell
Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -state Connected
```

This example sets an ESXi host's connection state to Connected.

### EXAMPLE 2

```powershell
Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -state Maintenance -vsanDataMigrationMode Full
```

This example sets an ESXi host's connection state to Maintenance with a Full data migration.

## PARAMETERS

### -esxiFqdn

The FQDN of the ESXi host.

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

### -state

The connection state to set the ESXi host to.
One of "Connected", "Disconnected", "Maintenance", or "NotResponding".

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

### -vsanDataMigrationMode

The vSAN data migration mode to use when setting the ESXi host to Maintenance.
One of "Full", "EnsureAccessibility", or "NoDataMigration".

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -timeout

The timeout in seconds to wait for the ESXi host to reach the desired connection state.
Default is 18000 seconds (5 hours).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 18000
Accept pipeline input: False
Accept wildcard characters: False
```

### -pollInterval

The poll interval in seconds to check the ESXi host connection state.
Default is 60 seconds.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 60
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
