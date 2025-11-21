import ContactItem from './ContactItem'
import './ContactList.css'

const ContactList = ({ contacts }) => {
  if (contacts.length === 0) {
    return (
      <div className="empty-contacts">
        <i className="fas fa-user-friends"></i>
        <p>No contacts found</p>
      </div>
    )
  }

  return (
    <div className="contact-list stagger-fade">
      {contacts.map((contact) => (
        <ContactItem key={contact.id} contact={contact} />
      ))}
    </div>
  )
}

export default ContactList
