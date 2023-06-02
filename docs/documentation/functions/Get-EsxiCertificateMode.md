# Get-EsxiCertificateMode

## SYNOPSIS

Retrieves the certificate management mode value from the vCenter Server instance for a workload domain.

## SYNTAX

```powershell
Get-EsxiCertificateMode [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [<CommonParameters>]
```

## DESCRIPTION

The Get-EsxiCertificateMode cmdlet retrieves the certificate management mode value from vCenter Server instance for a workload domain.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-EsxiCertificateMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
```

This example retrieves the certificate management mode value for the vCenter Server instance for the workload domain sfo-m01.

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

The name of the workload domain to retrieve the certificate management mode value for.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
