import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import axios from 'axios'

export default function Targets() {
  const queryClient = useQueryClient()
  const [showAddForm, setShowAddForm] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [newNotes, setNewNotes] = useState('')

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const response = await axios.get('/api/targets')
      return response.data.targets
    },
  })

  const addTarget = useMutation({
    mutationFn: async (data) => {
      await axios.post('/api/targets', data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['targets'])
      setShowAddForm(false)
      setNewDomain('')
      setNewNotes('')
    },
  })

  const removeTarget = useMutation({
    mutationFn: async (domain) => {
      await axios.delete(`/api/targets/${domain}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['targets'])
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    addTarget.mutate({
      domain: newDomain,
      notes: newNotes,
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Authorized Targets</h1>
          <p className="mt-2 text-slate-400">
            Manage domains authorized for penetration testing
          </p>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center px-4 py-2 text-sm font-medium text-white bg-cyan-500 rounded-lg hover:bg-cyan-600"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Target
        </button>
      </div>

      {/* Add Form */}
      {showAddForm && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Domain
              </label>
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="example.com"
                required
                className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Notes (Optional)
              </label>
              <textarea
                value={newNotes}
                onChange={(e) => setNewNotes(e.target.value)}
                placeholder="Authorization details, contact info, etc."
                rows={3}
                className="w-full px-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
            <div className="flex justify-end space-x-3">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-4 py-2 text-sm font-medium text-slate-300 bg-slate-700 rounded-lg hover:bg-slate-600"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={addTarget.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-cyan-500 rounded-lg hover:bg-cyan-600 disabled:opacity-50"
              >
                {addTarget.isPending ? 'Adding...' : 'Add Target'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Targets List */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
        {targets && targets.length > 0 ? (
          <table className="min-w-full divide-y divide-slate-700">
            <thead className="bg-slate-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">
                  Domain
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">
                  Scope
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">
                  Notes
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-slate-400 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-slate-800 divide-y divide-slate-700">
              {targets.map((target) => (
                <tr key={target.domain} className="hover:bg-slate-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm font-medium text-white">
                      {target.domain}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-1">
                      {target.scope_patterns?.slice(0, 2).map((pattern, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 text-xs text-slate-300 bg-slate-700 rounded"
                        >
                          {pattern}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-slate-400">
                      {target.notes || '-'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right">
                    <button
                      onClick={() => removeTarget.mutate(target.domain)}
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="px-6 py-12 text-center">
            <p className="text-slate-400">No authorized targets</p>
            <p className="mt-2 text-sm text-slate-500">
              Add a target to start scanning
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

