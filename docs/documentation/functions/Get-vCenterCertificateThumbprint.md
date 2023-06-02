# Get-vCenterCertificateThumbprint

## SYNOPSIS

Retrieves either all of the vCenter Server instance's certificate thumbprints or those which match the provided issuer name.

## SYNTAX

```powershell
Get-vCenterCertificateThumbprint [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [[-issuer] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Get-vCenterCertificateThumbprint cmdlet retrieves the vCenter Server instance's certificate thumbprints.
By default, it retrieves all thumbprints.
If issuer is provided, then only the thumbprint of the matching certificate is returned.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
```

This example retrieves the certificate thumbprints for the vCenter Server instance belonging to the domain sfo-m01.

### EXAMPLE 2

```powershell
Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole
```

This example retrieves the vCenter Server instance's certificate thumbprints for the vCenter Server instance belonging to domain sfo-m01 and a matching issuer "rainpole".

## PARAMETERS

### -server

The FQDN of the SDDC Manager.

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

The username to authenticate to SDDC Manager.

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

The password to authenticate to SDDC Manager.

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

The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

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

### -issuer

The name of the issuer to match with the vCenter Server instance's certificate thumbprints.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
