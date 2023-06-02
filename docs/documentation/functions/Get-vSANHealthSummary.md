# Get-vSANHealthSummary

## SYNOPSIS

Get the vSAN health summary from vCenter Server for a cluster.

## SYNTAX

```powershell
Get-vSANHealthSummary [-server] <String> [-user] <String> [-pass] <String> [-domain] <String>
 [-cluster] <String> [<CommonParameters>]
```

## DESCRIPTION

The Get-vSANHealthSummary cmdlet gets the vSAN health summary from vCenter Server for a cluster.
If any status is YELLOW or RED, a WARNING or ERROR will be raised.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-vSANHealthSummary -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01
```

This example gets the vSAN health summary for cluster sfo-m01-cl01.

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

The name of the cluster to retrieve the vSAN health summary for.

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

### Common Parameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).
