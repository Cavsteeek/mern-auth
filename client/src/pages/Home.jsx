import React from 'react'
import Navbar from '../components/Navbar.jsx'
import Header from '../components/Header.jsx'


const Home = () => {
  return (
    <div className='flex flec-col items-ceter justify-center min-h-screen bg-[url("/bg_img.png")] bg-cover bg-center'>
      <Header/>
      <Navbar />
    </div>
  )
}

export default Home
