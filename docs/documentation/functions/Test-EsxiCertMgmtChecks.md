# Test-EsxiCertMgmtChecks

## Synopsis

Run the checks required for ESXi Certificate Management for a given cluster or an ESXi host.

## Syntax

```powershell
Test-VCFCertMgmtChecks [-server] <String> [-user] <String> [-pass] <String> [-domain] <String> [-cluster] <String> [-signedCertificate] <String> [[-esxiFqdn] <String>] [[-issuer] <String>] [<CommonParameters>]
```

## Description

The `Test-VCFCertMgmtChecks` runs the checks required for ESXi Certificate Management for a given cluster or an ESXi host.

The following checks are run:

- Check ESXi Certificate Mode
- Check ESXi Lockdown Mode
- Confirm Certificate Authority in vCenter Server
- Check vSAN Health Status

## Examples

### Example 1

```powershell
Test-VCFCertMgmtChecks -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -issuer rainpole -signedCertificate F:\Certificates\Root64.cer
```

This example runs the checks required for ESXi Certificate Management for the cluster belonging to the domain sfo-m01.

### Example 2

```powershell
Test-VCFCertMgmtChecks -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -issuer rainpole -signedCertificate F:\Certificates\Root64.cer
```

This example runs the checks required for ESXi Certificate Management for an ESXi host belonging to the domain sfo-m01.

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

The password to authenticate to the SDDC Manager instance.

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

### -cluster

The name of the cluster in which the ESXi host is located.

```yaml
Type: String
Parameter Sets: cluster
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -signedCertificate

The complete path for the root certificate file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -issuer

The name of the issuer to match with the thumbprint.

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

### -esxiFqdn

The fully qualified domain name of the ESXi host.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
