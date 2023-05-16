# Get-EsxiConnectionState

## SYNOPSIS

Get the ESXi host connection state from vCenter Server.

## SYNTAX

```powershell
Get-EsxiConnectionState [-esxiFqdn] <String> [<CommonParameters>]
```

## DESCRIPTION

The Get-EsxiConnectionState cmdlet gets the connection state of an ESXi host.
One of "Connected", "Disconnected", "Maintenance", or "NotResponding"
Depends on a connection to a vCenter Server instance.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
```

This example gets an ESXi host's connection state.

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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
