section AmazonS3;

ParseHost = (hostname as text) =>
    let
        service = "s3",
        serviceDash = service & "-",
        host = Text.Split(hostname, "."),
        bucket = if host{0} = service or Text.StartsWith(host{0}, serviceDash) then null else host{0},
        host2 = if bucket = null then host else List.Skip(host, 1),
        host3 = if Text.StartsWith(host2{0}, serviceDash) then {service, Text.Range(host2{0}, 3)} & List.Skip(host2, 1) else host2,
        n = List.Count(host3),
        region = if host3{0} <> service or n < 3 or n > 4 or host3{n-2} <> "amazonaws" or host3{n-1} <> "com" then error "unrecognized URL" else if n = 3 then "us-east-1" else host3{1}
    in
        [service=service, region=region, bucket=bucket];

MakeSigningKey = (keySecret, today, region, service, constant) =>
    let
        today = DateTimeZone.ToText(DateTimeZone.UtcNow(), "yyyyMMdd"),
        secret = Text.ToBinary("AWS4" & keySecret, TextEncoding.Utf8),
        hashDate = Crypto.CreateHmac(CryptoAlgorithm.SHA256, secret, Text.ToBinary(today, TextEncoding.Utf8)),
        hashRegion = Crypto.CreateHmac(CryptoAlgorithm.SHA256, hashDate, Text.ToBinary(region, TextEncoding.Utf8)),
        hashService = Crypto.CreateHmac(CryptoAlgorithm.SHA256, hashRegion, Text.ToBinary(service, TextEncoding.Utf8)),
        signingKey = Crypto.CreateHmac(CryptoAlgorithm.SHA256, hashService, Text.ToBinary(constant, TextEncoding.Utf8))
    in
        signingKey;

BuildQueryString = (r) =>
    let
        names = List.Sort(Record.FieldNames(r)),
        sorted = Record.ReorderFields(r, names),
        table = Table.FromColumns({names, Record.FieldValues(sorted)}),
        added = Table.AddColumn(table, "New", each [Column1] & "=" & Uri.EscapeDataString([Column2]))
    in
        Text.Combine(added[New], "&");

Table.ToNavigationTable = (table as table, nameColumn as text, dataColumn as text, isLink as logical) =>
    let
        tableType = Value.Type(table),
        rowType = Type.TableRow(tableType),
        rowFields = Type.RecordFields(rowType),
        dataColumnField = Record.Field(rowFields, dataColumn),
        dataColumnType = dataColumnField[Type],

        newDataColumnType = if isLink then dataColumnType meta [Link = "Table", LinkName = "Table"] else dataColumnType,
        newDataColumnField = dataColumnField & [Type = newDataColumnType],
        newRowFields = rowFields & Record.FromList({newDataColumnField}, {dataColumn}),
        newRowType = Type.ForRecord(newRowFields, Type.IsOpenRecord(rowType)),
        newTableType = (type table newRowType) meta [Name = nameColumn, Data = dataColumn],

        tableWithKey = Table.Distinct(table, nameColumn),
        navigationTable = Value.ReplaceType(tableWithKey, newTableType)
    in
        navigationTable;

MakeDirectory = (content, url) =>
    let
        xml = Xml.Tables(content),
        contents = xml{0}[Contents],
        changedType = Table.TransformColumnTypes(contents,{{"Key", type text}, {"LastModified", type datetime}, {"ETag", type text}, {"Size", Int64.Type}, {"StorageClass", type text}}),
        renamed = Table.RenameColumns(changedType, {"Key", "path"}),
        withContent = Table.AddColumn(renamed, "Content", each S3.Contents(url & "/" & [path])),
        reordered = Table.ReorderColumns(withContent,{"Content", "path", "LastModified", "ETag", "Size", "Owner", "StorageClass"})
    in
        reordered;

MakeBucketList = (content, url) =>
    let
        xml = Xml.Tables(content),
        filtered = Table.SelectRows(xml, each [Name] = "Buckets"),
        table = filtered{0}[Table]{0}[Table],
        narrowed = Table.SelectColumns(table,{"Name"}),
        changedType = Table.TransformColumnTypes(table,{{"Name", type text}}),
        withDirectory = Table.AddColumn(changedType, "Data", each S3.Contents(url & "/" & [Name])),
        asNav = Table.ToNavigationTable(withDirectory, "Name", "Data", false)
    in
        asNav;

S3.Contents = (url as text) =>
    let
        credential = Extension.CurrentCredential(),
        keyId = credential[Username],
        now = DateTimeZone.UtcNow(),
        today = DateTimeZone.ToText(now, "yyyyMMdd"),
        time = DateTimeZone.ToText(now, "yyyyMMddTHHmmssZ"),
        parts = Uri.Parts(url),
        parsedHost = ParseHost(parts[Host]),
        service = parsedHost[service],
        region = parsedHost[region],
        constant = "aws4_request",
        signingKey = MakeSigningKey(credential[Password], today, region, service, constant),
        canonicalUri = parts[Path],
        queryString = BuildQueryString(parts[Query]),
        headers = "host:" & parts[Host] & "#(lf)x-amz-date:" & time,
        headersList = "host;x-amz-date",
        contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonicalRequest = Text.Combine({"GET", canonicalUri, queryString, headers, "", headersList, contentHash}, "#(lf)"),
        hashedRequest = Binary.ToText(Crypto.CreateHash(CryptoAlgorithm.SHA256, Text.ToBinary(canonicalRequest, TextEncoding.Utf8)), BinaryEncoding.Hex),
        id = today & "/" & region & "/" & service & "/" & constant,
        stringToSign = "AWS4-HMAC-SHA256#(lf)" & time & "#(lf)" & id & "#(lf)" & hashedRequest,
        signature = Crypto.CreateHmac(CryptoAlgorithm.SHA256, signingKey, Text.ToBinary(stringToSign, TextEncoding.Utf8)),
        auth = "AWS4-HMAC-SHA256 Credential=" & keyId & "/" & id & ", SignedHeaders=host;x-amz-date, Signature=" & Binary.ToText(signature, BinaryEncoding.Hex),
        content = Web.Contents(url, [Headers=[#"x-amz-date"=time, Authorization=auth, #"x-amz-content-sha256"=contentHash], ExcludedFromCacheKey={"x-amz-date", "Authorization"}]),
        bucket = if canonicalUri = "/" then parsedHost[bucket] else if parsedHost[bucket] = null and Text.PositionOf(canonicalUri, "/", 1) < 0 then Text.Range(canonicalUri, 1) else null,
        result = if bucket <> null then MakeDirectory(content, url) else if canonicalUri = "/" then MakeBucketList(content, url) else content
    in
        result;

[DataSource.Kind = "AmazonS3", Publish="AmazonS3.Publish"]
shared AmazonS3.Contents = Value.ReplaceType(S3.Contents, type function (url as Uri.Type) as table);

AmazonS3 = [
    Authentication=[UsernamePassword=[UsernameLabel="", PasswordLabel=""]],
    Label = Extension.LoadString("DataSourceLabel")
];

// Data Source UI publishing description
AmazonS3.Publish = [
    Beta = true,
    Category = "Other",
    ButtonText = { Extension.LoadString("ButtonTitle"), Extension.LoadString("ButtonHelp") },
    LearnMoreUrl = "https://powerbi.microsoft.com/",
    SourceImage = AmazonS3.Icons,
    SourceTypeImage = AmazonS3.Icons
];

AmazonS3.Icons = [
    Icon16 = { Extension.Contents("AmazonS3_16.png"), Extension.Contents("AmazonS3_20.png"), Extension.Contents("AmazonS3_24.png"), Extension.Contents("AmazonS3_32.png") },
    Icon32 = { Extension.Contents("AmazonS3_32.png"), Extension.Contents("AmazonS3_40.png"), Extension.Contents("AmazonS3_48.png"), Extension.Contents("AmazonS3_64.png") }
];
