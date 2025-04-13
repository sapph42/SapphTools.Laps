using System;
using System.Collections.Generic;

namespace SapphTools.Laps.Internal;
internal class DescendingDateTimeComparer : IComparer<DateTime> {
    public int Compare(DateTime x, DateTime y) {
        return y.CompareTo(x);
    }
}