import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Book } from 'lucide-react'
import axios from 'axios'

export default function KnowledgeBase() {
  const [searchQuery, setSearchQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  const { data: results, isLoading } = useQuery({
    queryKey: ['knowledge-base', debouncedQuery],
    queryFn: async () => {
      if (!debouncedQuery) return []
      const response = await axios.get('/api/knowledge-base/search', {
        params: { query: debouncedQuery, limit: 10 },
      })
      return response.data.results
    },
    enabled: debouncedQuery.length > 2,
  })

  const handleSearch = (e) => {
    e.preventDefault()
    setDebouncedQuery(searchQuery)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Knowledge Base</h1>
        <p className="mt-2 text-slate-400">
          Search pentesting methodologies, techniques, and best practices
        </p>
      </div>

      {/* Search */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <form onSubmit={handleSearch}>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search for pentesting techniques, vulnerabilities, etc."
              className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </form>
      </div>

      {/* Results */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="text-center py-12 text-slate-400">Searching...</div>
        ) : results && results.length > 0 ? (
          results.map((result, index) => (
            <div
              key={index}
              className="bg-slate-800 border border-slate-700 rounded-lg p-6"
            >
              <div className="flex items-start">
                <div className="flex-shrink-0">
                  <div className="p-2 bg-cyan-500/10 rounded-lg">
                    <Book className="w-5 h-5 text-cyan-400" />
                  </div>
                </div>
                <div className="ml-4 flex-1">
                  <h3 className="text-lg font-semibold text-white">
                    {result.title}
                  </h3>
                  {result.category && (
                    <span className="inline-block mt-2 px-2 py-1 text-xs font-medium text-cyan-400 bg-cyan-500/10 rounded-full">
                      {result.category}
                    </span>
                  )}
                  <p className="mt-3 text-sm text-slate-300 leading-relaxed">
                    {result.content}
                  </p>
                  {result.tags && result.tags.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {result.tags.map((tag, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 text-xs text-slate-400 bg-slate-700 rounded"
                        >
                          #{tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : debouncedQuery.length > 2 ? (
          <div className="text-center py-12">
            <p className="text-slate-400">No results found</p>
            <p className="mt-2 text-sm text-slate-500">
              Try different keywords or search terms
            </p>
          </div>
        ) : (
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-12 text-center">
            <Book className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">
              Enter a search query to find relevant pentesting knowledge
            </p>
            <p className="mt-2 text-sm text-slate-500">
              Try searching for "SQL injection", "XSS", "CSRF", etc.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

