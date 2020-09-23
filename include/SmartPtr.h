/*
   Copyright (C) 2020 by Sarat Kumar Behera <beherasaratkumar@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file SmartPtr.h
 * @brief New and improved implementation of Smart pointer class for handling
 *        deletion of pointers automatically.
 *        This version is a thread-safe implmentation of the smart pointer class.
 *        However, the internal pointer itself is not thread-safe. It should be
 *        taken care of by the implementer of that datatype.
 *
 *        1) All structs and classes MUST be derived from SmartRef in-order to use SmartPtr.
 *           Any attempt to use it without deriving from SmartRef will result
 *           in a compiler error.
 *        2) Safe datatypes like int, char, bool etc. can be used directly.
 *           See example (1) for details.
 *        3) Any union or pre-defined struct/classes must be encapsulated in
 *           SmartRefContainer before using it in SmartPtr.
 *           See example (2) for details.
 *
 * @example
 *       (1) SmartPtr<int> p1 = new int;
 *           {
 *             // Increments the reference count on the smart pointer
 *             SmartPtr<int> p2 = p1;
 *             // As we leave this scope the reference count is decremented by one
 *           }
 *           // In the above example when p1 goes out of scope, it will be
 *           // destroyed automatically using SmartPtr_delete()
 *
 *           SmartPtr<int, SmartPtr_free> x1 = (int) malloc(sizeof(int));
 *           // In the above example when x1 goes out of scope, it will be
 *           // destroyed automatically using SmartPtr_free()
 *
 *       (2) typedef SmartPtr< SmartRefContainer<struct tm> > struct_tmPtr;
 *           time_t now = time(NULL);
 *           struct_tmPtr tm1 = SmartRefContainer<struct tm>::create_SmartPtr(new struct tm);
 *           localtime_r(&now, tm1.ptr()->ptr()); // NOTE .ptr()->ptr()
 *           {
 *             struct_tmPtr tm2 = tm1; // reference count incremented
 *           } // reference count decremented
 *           cout << tm1.ptr()->ptr()->tm_sec << endl;
 *
 * @note THE FOLLOWING SCENARIOS MUST BE AVOIDED for non-struct/class SmartPtr:
 *       ======================================================================
 *       1) SmartPtr<int> p1 = new int;
 *          SmartPtr<int> p2 = p1.ptr(); // DANGEROUS. p2 will create a new internal reference, for the same pointer as p1
 *                                          Both p1 and p2 will try destroying the same pointer, the second delete will crash.
 *
 */
#ifndef _SMARTPTR_
#define _SMARTPTR_

#include <type_traits>
#include <typeinfo>
#include <atomic>

#include <iostream>
using namespace std;

/**
 * @class SmartRef
 * @brief Any class or struct planning use SmartPtr should derive from SmartRef class
 *        for better handling of smart pointer
 */
class SmartRef
{
public:
  SmartRef() :  __refcount__value(0) {}
  SmartRef(const SmartRef&) : __refcount__value(0) {}
  SmartRef& operator=(const SmartRef&) { return *this; }
  virtual ~SmartRef() {}
  // Allow SmartPtr to access the private members
  template <class U, void (*pfnDelete)(U*)> friend class SmartPtr;
private:
  mutable std::atomic<int> __refcount__value;
};

//! Destroy the pointer using c++ delete operator
template <class T> void SmartPtr_delete(T* ptr) { if ( ptr ) delete ptr; }
//! Destroy the pointer using c++ delete[] operator
template <class T> void SmartPtr_deleteArr(T* ptr) { if ( ptr ) delete[] ptr; }
//! Destroy the pointer using c++ free operator
template <class T> void SmartPtr_free(T* ptr) { if ( ptr ) free(ptr); }

/**
 * @brief A template class for handling smart pointers.
 *        Users only have to allocate pointers using "new".
 *        Deletion is taken care of automatically.
 */
template <class T, void (*pfnDelete)(T*) = SmartPtr_delete> class SmartPtr
{
public:
  //! Any struct or class MUST be derived from SmartRef to be used as a SmartPtr
  static_assert(!std::is_class<T>::value || std::is_base_of<SmartRef, T>::value, "T must inherit from SmartRef");
  /**
   * @brief Prevent using union as a SmartPtr because it cannot be derived from a structure
   *        However, the main reason for preventing it is the danger of assigning the
   *        "this" pointer to a SmartPtr within any function in the union.
   */
  static_assert(!std::is_union<T>::value, "We do not allow creating smart pointer with union to prevent mis-usage of this pointer");

  //! Default constructor
  SmartPtr() : m_data(nullptr) {}
  //! One-arg constructor. Starts a fresh object with reference count 1. May throw T* exception
  SmartPtr(T* ptr) : m_data(nullptr) { p_assign(ptr); }
  //! Copy constructor (Increments the reference count)
  SmartPtr(const SmartPtr& obj) : m_data(nullptr) { p_assign(obj); }
  //! Virtual destructor. Releases the smart pointer by decrementing the reference count.
  virtual ~SmartPtr() { p_release(); }

  //! Returns the pointer to the object
  T* ptr() const { return p_get(m_data); }
  //! Checks whether the smart pointer is empty or not
  bool empty() const { return !p_get(m_data); }
  //! Clears the smart pointer by decrementing the reference count.
  void clear() { p_release(); m_data = nullptr; }

  // scope resolution operators ( throws a std::string() error if it is a null pointer)
  const T* operator ->() const throw (std::string) { throw_if_empty(); return p_get(m_data); }
  T* operator ->() throw (std::string) { throw_if_empty(); return p_get(m_data); }
  const T& operator *() const throw (std::string) { throw_if_empty(); return *(p_get(m_data)); }
  T& operator *() throw (std::string) { throw_if_empty(); return *(p_get(m_data)); }

  // condition checking operators
  bool operator ==(T* ptr) const { return (this->ptr() == ptr); }
  bool operator ==(const SmartPtr& obj) const { return (m_data == obj.m_data); }
  bool operator !=(T* ptr) const { return (this->ptr() != ptr); }
  bool operator !=(const SmartPtr& obj) const { return (m_data != obj.m_data); }
  bool operator !() const { return (!m_data || !p_get(m_data)); }
  operator void*() const { return this->ptr(); }
  int refCount() const { return getRefCount(); }

  // assignment operators
  //! Starts a fresh object with reference count 1. May throw T* exception
  SmartPtr& operator =(T* ptr) { return p_assign(ptr); }
  SmartPtr& operator =(const SmartPtr& obj) { return p_assign(obj); }

//////////////////////////
//
// private members
//
//////////////////////////
private:
  struct SmartRefHelper
  {
  public:
    static SmartRef* allocate(T* ptr)
    {
      //cout << "Calling SmartRefHelper allocate" << endl;
      return dynamic_cast<SmartRef*>(ptr);
    }
    static void deallocate(SmartRef* pData)
      {
        if ( pData )
        {
          // Get T* and delete, or can we delete pData directly?
          T* p = get(pData);
          if ( p ) (*pfnDelete)(p);
        }
      }
    static T* get(SmartRef* pData)
      {
        if ( !pData ) return nullptr;
        T* p = dynamic_cast<T*>(pData);
        if ( !p )
        {
          ///////////////////////////////////////////////////////////////////////////////////
          //
          //                    ***** THIS IS A SPECIAL CASE ******
          //
          ////////////////////////////////////////////////////////////////////////////////////
          // This can happen when the upcasting class inherits SmartRef as private/protected.
          // In this case, a dynamic_cast would return nullptr.
          // So, we cast it using static_cast first, and then do a dynamic_cast.
          // ***** If something is wrong, we need to revisit this code. *****
          ////////////////////////////////////////////////////////////////////////////////////
          p = dynamic_cast<T*>(static_cast<T*>(pData));
          //cout << "Calling SmartRefHelper get: [" << pData << "] " << data << endl;
        }
        return p;
      }
  };

  struct SmartRefEx : public SmartRef
  {
  private:
    T* ptr;
    SmartRefEx(T* p) : ptr(p) {}

  public:
    static SmartRef* allocate(T* ptr)
      {
        //cout << "Calling SmartRefEx allocate" << endl;
        SmartRefEx* pDataEx = nullptr;
        if ( ptr )
        {
          // allocate memory for handling smart pointer
          pDataEx = new SmartRefEx(ptr);
          // if memory allocation failed, throw "ptr" as an exception
          // the caller must use catch() and perform necessary cleanup action on ptr
          if ( pDataEx == nullptr ) throw ptr;
        }
        return dynamic_cast<SmartRef*>(pDataEx);
      }
    static void deallocate(SmartRef* pData)
      {
        if ( pData )
        {
          T* p = get(pData);
          if ( p ) (*pfnDelete)(p);
          delete pData;
        }
      }
    static T* get(SmartRef* pData)
      {
        if ( !pData ) return nullptr;
        SmartRefEx* pDataEx = dynamic_cast<SmartRefEx*>(pData);
        return ( pDataEx )? pDataEx->ptr : nullptr;
      }
  };

#define IS_ALREADY_SMARTREF (std::is_base_of<SmartRef, T>::value != 0)
  typedef typename std::conditional<IS_ALREADY_SMARTREF, SmartRefHelper, SmartRefEx>::type SmartData;
  SmartRef* m_data; // internal smart pointer object

private:
  int incRefCount() { return (!m_data)?  0:++m_data->__refcount__value; }
  int decRefCount() { return (!m_data)? -1:--m_data->__refcount__value; }
  int getRefCount() const { return (!m_data)? 0:m_data->__refcount__value.load(); }
  void throw_if_empty() const throw (std::string) { if ( empty() ) throw std::string("Cannot reference null pointer"); }

  T* p_get(SmartRef* pData) const { return SmartData::get(pData); }

  SmartPtr& p_assign(T* ptr)
  {
    // Perform assignment only when both pointers are differnt
    if ( this->ptr() != ptr )
    {
      p_release();
      m_data = SmartData::allocate(ptr);
      incRefCount();
    }
    return *this;
  }

  SmartPtr& p_assign(const SmartPtr& obj)
  {
    // Perform assignment only when both pointers are differnt
    if ( m_data != obj.m_data )
    {
      p_release();
      m_data = obj.m_data;
      incRefCount();
    }
    return *this;
  }

  /**
   * @brief releases the smart pointer object
   */
  void p_release()
  {
    // 1) decrement the reference count
    // 2) if the reference count is zero, delete both the pointers
    if ( m_data != nullptr && decRefCount() == 0 )
    {
      SmartData::deallocate(m_data);
      m_data = nullptr;
    }
  }
};

/**
 * @class SmartRefContainer
 * @brief Used as SmartRef container class to support unions and c-defined structs
 */
template <class T, void (*pfnDelete)(T*) = SmartPtr_delete> class SmartRefContainer : public SmartRef
{
public:
  //! The only way to create this object
  static SmartPtr< SmartRefContainer<T, pfnDelete> > create_SmartPtr(T* p) throw (T*)
  {
    SmartPtr< SmartRefContainer<T, pfnDelete> > ptr;
    if ( p )
    {
      try { ptr = new SmartRefContainer(p); } catch (...) { throw p; }
      if ( ptr.empty() ) throw p;
    }
    return ptr;
  }
  //! Destructor
  ~SmartRefContainer() { if ( m_p ) (*pfnDelete)(m_p); }
  //! Checks for empty
  bool empty() const { return (m_p == nullptr); }
  //! Returns the pointer associated with this class
  T* ptr() const { return m_p; }

private:
  T* m_p;

private:
  //! Private constructor
  SmartRefContainer(T* p) : m_p(p) {}
  SmartRefContainer(const SmartRefContainer&); // Copy construction is not allowed
  SmartRefContainer& operator=(const SmartRefContainer&); // Copy operation is not allowed
};

#endif // _SMARTPTR_
