using System.Collections.ObjectModel;

namespace RK.Extensions.TypeExtensions
{
    /// <summary>
    /// Extensions for <seealso cref="IEnumerable{T}"/> Collections
    /// </summary>
    public static class EnumerableExtensions
    {
        /// <summary>
        /// Converts an <seealso cref="IEnumerable{T}"/> in an <seealso cref="ObservableCollection{T}"/>
        /// </summary>
        /// <typeparam name="T">Target Type</typeparam>
        /// <param name="collection">Collection of type <seealso cref="IEnumerable{T}"/></param>
        /// <returns>Converted <paramref name="collection"/></returns>
        public static ObservableCollection<T> ToObservableCollection<T>(this IEnumerable<T> collection)
        {
            if (collection is null)
            {
                throw new ArgumentException("Collection must be not null", nameof(collection));
            }

            return new ObservableCollection<T>(collection);
        }
    }
}