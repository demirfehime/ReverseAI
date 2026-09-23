param([Parameter(Mandatory=$true)][string]$ImagePath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Runtime.WindowsRuntime
Add-Type -AssemblyName System.Drawing
# Create a deterministic OCR-only derivative: dark colored glyphs on a dark
# background need contrast normalization. The original artifact stays intact.
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
public static class OCRContrast {
    public static void Normalize(string input, string output) {
        using (Bitmap source = new Bitmap(input))
        using (Bitmap target = new Bitmap(source.Width, source.Height, PixelFormat.Format24bppRgb)) {
            if (source.Width * (long)source.Height > 10000000) throw new Exception("Image too large");
            for (int y=0; y<source.Height; y++) for (int x=0; x<source.Width; x++) {
                Color c = source.GetPixel(x,y);
                int brightness = Math.Max(c.R, Math.Max(c.G,c.B));
                target.SetPixel(x,y, brightness >= 120 ? Color.Black : Color.White);
            }
            target.Save(output, ImageFormat.Png);
        }
    }
}
'@
$normalized = $ImagePath + '.ocr.png'
[OCRContrast]::Normalize($ImagePath, $normalized)
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType=WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType=WindowsRuntime]
$null = [Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType=WindowsRuntime]
$null = [Windows.Globalization.Language, Windows.Globalization, ContentType=WindowsRuntime]
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1
function AwaitOperation($Operation, [Type]$ResultType) {
    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $task.GetAwaiter().GetResult()
}
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US'))
if ($null -eq $engine) { throw 'Windows English OCR language is unavailable' }
$variants = @()
foreach ($variantPath in @($ImagePath, $normalized)) {
    $file = AwaitOperation ([Windows.Storage.StorageFile]::GetFileFromPathAsync($variantPath)) ([Windows.Storage.StorageFile])
    $stream = AwaitOperation ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    try {
        $decoder = AwaitOperation ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $bitmap = AwaitOperation ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        try {
            $result = AwaitOperation ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
            $variants += @{text=$result.Text; image=$variantPath}
        } finally { $bitmap.Dispose() }
    } finally { $stream.Dispose() }
}
@{text=$variants[0].text; engine='Windows.Media.Ocr/en-US'; alternatives=$variants; needs_visual_review=$true} | ConvertTo-Json -Depth 4 -Compress
