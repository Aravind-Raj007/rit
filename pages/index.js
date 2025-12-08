import { useEffect, useState } from 'react'
import Head from 'next/head'
import AuthPage from '../components/AuthPage'
import Dashboard from '../components/Dashboard'

export default function Home() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check if user is already logged in
    const checkAuth = async () => {
      if (typeof window !== 'undefined' && window.electronAPI) {
        try {
          const currentUser = await window.electronAPI.getCurrentUser()
          if (currentUser && currentUser.userId) {
            setUser(currentUser)
          }
        } catch (error) {
          console.error('Failed to check auth:', error)
        }
      }
      setLoading(false)
    }

    checkAuth()
  }, [])

  const handleAuthSuccess = (userData) => {
    setUser(userData)
  }

  const handleLogout = () => {
    setUser(null)
  }

  if (loading) {
    return (
      <>
        <Head>
          <title>SIMPLIFIED CYBER DEFENCE FOR THREATS</title>
          <meta name="viewport" content="width=device-width, initial-scale=1" />
        </Head>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          color: 'white',
          fontSize: '18px'
        }}>
          Loading SIMPLIFIED CYBER DEFENCE FOR THREATS...
        </div>
      </>
    )
  }

  return (
    <>
      <Head>
        <title>SIMPLIFIED CYBER DEFENCE FOR THREATS</title>
        <meta name="description" content="Personal Cybersecurity Tool" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      {!user ? (
        <AuthPage onAuthSuccess={handleAuthSuccess} />
      ) : (
        <Dashboard user={user} onLogout={handleLogout} />
      )}
    </>
  )
}

