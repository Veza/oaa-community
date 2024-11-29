class CerbyUser:
    def __init__(self, id: int, first_name: str, last_name: str, email: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: int) -> None:
        if not isinstance(value, int):
            raise ValueError("ID must be an integer")
        self._id = value

    @property
    def first_name(self) -> str:
        return self._first_name

    @first_name.setter
    def first_name(self, value: str) -> None:
        if not isinstance(value, str):
            raise ValueError("First name must be a string")
        self._first_name = value

    @property
    def last_name(self) -> str:
        return self._last_name

    @last_name.setter
    def last_name(self, value: str) -> None:
        if not isinstance(value, str):
            raise ValueError("Last name must be a string")
        self._last_name = value

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if "@" not in value:
            raise ValueError("Invalid email address")
        self._email = value