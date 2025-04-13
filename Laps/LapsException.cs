using System;

namespace SapphTools.Laps;
/// <summary>
/// Extends <see cref="Exception"/>. Does not provide additional functionality.
/// </summary>
public class LapsException : Exception {
    /// <summary>
    /// Forwards to <see cref="Exception(string)"/>.
    /// </summary>
    /// <param name="message"></param>
    public LapsException(string message)
        : base(message) {
    }
    /// <summary>
    /// Default constructor.
    /// </summary>
    public LapsException() {
    }
}