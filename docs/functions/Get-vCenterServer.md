# Get-vCenterServer

## SYNOPSIS

Retrieves the vCenter Server details and connection object from SDDC Manager using either a workload domain name or ESXi host FQDN.

## SYNTAX

### domain

```powershell
Get-vCenterServer -server <String> -user <String> -pass <String> -domain <String> [<CommonParameters>]
```

### esxifqdn

```powershell
Get-vCenterServer -server <String> -user <String> -pass <String> -esxiFqdn <String> [<CommonParameters>]
```

## DESCRIPTION

The Get-vCenterServer retrieves the vCenter Server details and connection object from SDDC Manager using either a workload domain name or ESXi host FQDN.
The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.

- Validates that network connectivity and authentication is possible to SDDC Manager.
- Validates that network connectivity and authentication is possible to vCenter Server.
- Validates that the workload domain exists in the SDDC Manager inventory.
- Connects to vCenter Server and returns its details and connection in a single object.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
```

This example retrieves the vCenter Server details and connection object to which the ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io belongs.

### EXAMPLE 2

```powershell
Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01

```

This example retrieves the vCenter Server details and connection object belonging to the domain sfo-m01.

## PARAMETERS

### -server

The FQDN of the SDDC Manager appliance.

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

The username to authenticate to SDDC Manager.

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

The password to authenticate to SDDC Manager.

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

The name of the workload domain to retrieve the vCenter Server details from SDDC Manager for the connection object.

```yaml
Type: String
Parameter Sets: domain
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -esxiFqdn

The FQDN of the ESXi host to validate against the SDDC Manager inventory.

```yaml
Type: String
Parameter Sets: esxifqdn
Aliases:

Required: True
Position: Named
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
