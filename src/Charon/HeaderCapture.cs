using System.Buffers;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Charon;

/// <summary>Turns HTTP headers into the JSON recorded in the traffic database.</summary>
internal static class HeaderCapture
{
    private const string RedactedValue = "[redacted]";

    /// <summary>Headers whose values are secrets as a matter of course.</summary>
    private static readonly HashSet<string> SecretHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
        "X-Api-Key", "Api-Key", "X-Auth-Token",
    };

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        // This goes in a database, not in a page, so it can stay readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Makes a JSON array of pairs of names and values, keeping the order and any repeats.
    /// </summary>
    /// <param name="headers">The headers.</param>
    /// <param name="maxBytes">
    /// Approximate limit on the length of the result.  Headers past this are left out, and
    /// a last pair of "(truncated)" marks that.  Clients get to decide what is in here,
    /// so that what they cause to be kept in memory has to be bounded.
    /// </param>
    /// <param name="credential">
    /// What was injected into the request.  Should a server repeat it, in a header
    /// that would be otherwise innocuous, then it must not be recorded.
    /// </param>
    public static string ToJson(IHeaderDictionary headers, int maxBytes, CredentialValue? credential)
    {
        var buffer = new ArrayBufferWriter<byte>(1024);

        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartArray();

            foreach (var (name, values) in headers)
            {
                foreach (var value in values)
                {
                    if (writer.BytesCommitted + writer.BytesPending + name.Length + (value?.Length ?? 0) > maxBytes)
                    {
                        WritePair(writer, "(truncated)", "");
                        goto done;
                    }

                    bool secret = SecretHeaders.Contains(name) ||
                                  (value is not null && credential?.AppearsIn(value) == true);
                    WritePair(writer, name, secret ? RedactedValue : value);
                }
            }

        done:
            writer.WriteEndArray();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WritePair(Utf8JsonWriter writer, string name, string? value)
    {
        writer.WriteStartArray();
        writer.WriteStringValue(name);
        writer.WriteStringValue(value);
        writer.WriteEndArray();
    }
}
