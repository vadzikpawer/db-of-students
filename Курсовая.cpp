#define _CRT_SECURE_NO_WARNINGS
#define PATH "Students.txt"
#define line for (int j = 0; j < 60; j++) cout << "-"; cout << "\n";

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

using namespace std;

struct Sub {
	char* name = new char[21];
	int* mark = new int();
};

class Mystr {
private:
	char* data = nullptr;

public:
	Mystr(const char in[]) {
		data = new char[strlen(in) + 1]();
		for (int i = 0; i < strlen(in); i++) {
			*(data + i) = in[i];
		}
		data[strlen(data)] = '\0';
	}

	~Mystr() {
		delete[] data;
	}

	void operator += (const char other[]) {
		char* temp = new char[strlen(data) + strlen(other) + 1]();
		int i = 0;
		for (; i < strlen(data); i++) {
			*(temp + i) = *(data + i);
		}
		for (int j = 0; j < strlen(other); j++) {
			*(temp + i + j) = *(other + j);
		}
		temp[strlen(temp)] = '\0';

		delete[] data;

		data = new char[strlen(temp) + 1]();
		for (i = 0; i < strlen(temp); i++) {
			*(data + i) = *(temp + i);
		}
		data[strlen(data)] = '\0';
	}

	char* Get() {
		return data;
	}
};

class Crypto {
private:
	char* Gen_pass() {
		srand(time(NULL));
		char* pass = new char[17];
		for (int i = 0; i < 16; ++i)
		{
			switch (rand() % 3) {
			case 0:
				pass[i] = rand() % 10 + '0';
				break;
			case 1:
				pass[i] = rand() % 26 + 'A';
				break;
			case 2:
				pass[i] = rand() % 26 + 'a';
			}
		}
		pass[16] = '\0';

		return pass;
	}

public:
	void Encrypt() {
		Mystr PATH_ENC(PATH);
		PATH_ENC += ".enc";

		ifstream File;
		File.open(PATH, ios::binary);
		ofstream File_enc;
		File_enc.open(PATH_ENC.Get(), ios::binary | ios::app);
		File_enc.seekp(0, ios::beg);

		int length;
		File.seekg(0, ios::end);
		length = File.tellg();
		File.seekg(0, ios::beg);

		char* szPassword = Gen_pass();

		int dwLength = strlen(szPassword);
		File_enc.write((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_len = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_len;
		DWORD dwBufferLen = 0;

		if (enc_len > 1)
		{
			dwBufferLen = dwBlockLen + enc_len;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = 0;
		bool final = false;

		while (count != length) {
			if (length - count < dwBlockLen) {
				dwBlockLen = length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBufferLen]();
			File.read((char*)temp, dwBlockLen);

			if (!CryptEncrypt(hKey, NULL, final, 0, temp, &dwBlockLen, dwBufferLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File_enc.write((char*)temp, dwBlockLen);

			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();

		if (remove(PATH) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}

	void Decrypt() {
		Mystr PATH_ENC(PATH);
		PATH_ENC += ".enc";

		ofstream File;
		File.open(PATH, ios::binary | ios::app);
		ifstream File_enc;
		File_enc.open(PATH_ENC.Get(), ios::binary);

		int length;
		File_enc.seekg(0, ios::end);
		length = File_enc.tellg();
		File_enc.seekg(0, ios::beg);

		if (length == -1 || length == 0) {
			return;
		}

		int dwLength = 16;
		char* szPassword = new char[dwLength];
		File_enc.read((char*)szPassword, dwLength + 1);

		HCRYPTPROV hProv;
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			cout << "Error during CryptAcquireContext!";
		}

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			cout << "Error during CryptCreateHash!";
		}

		if (!CryptHashData(hHash, (BYTE*)szPassword, (DWORD)dwLength, 0))
		{
			cout << "Error during CryptHashData!";
		}

		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
		{
			cout << "Error during CryptDeriveKey!";
		}

		size_t enc_len = 8;
		DWORD dwBlockLen = 1000 - 1000 % enc_len;
		DWORD dwBufferLen = 0;

		if (enc_len > 1)
		{
			dwBufferLen = dwBlockLen + enc_len;
		}
		else
		{
			dwBufferLen = dwBlockLen;
		}

		int count = strlen(szPassword) + 1;
		bool final = false;

		while (count != length) {
			if (length - count < dwBlockLen) {
				dwBlockLen = length - count;
				final = true;
			}

			BYTE* temp = new BYTE[dwBlockLen];
			File_enc.read((char*)temp, dwBlockLen);

			if (!CryptDecrypt(hKey, 0, final, 0, temp, &dwBlockLen))
			{
				cout << "Error during CryptEncrypt. \n";
			}

			File.write((char*)temp, dwBlockLen);
			count = count + dwBlockLen;
		}

		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				cout << "Error during CryptDestroyHash";
		}

		if (hKey)
		{
			if (!(CryptDestroyKey(hKey)))
				cout << "Error during CryptDestroyKey";
		}

		if (hProv)
		{
			if (!(CryptReleaseContext(hProv, 0)))
				cout << "Error during CryptReleaseContext";
		}

		File.close();
		File_enc.close();
		if (remove(PATH_ENC.Get()) != 0) {
			cout << "ERROR -- ошибка при удалении файла\n";
		}
	}
};

class Program {
public:
	
	void print(char* val) {
		cout << val;
	}

	void print(int val) {
		cout << val;
	}
	
	void print(const char val[]) {
		cout << val;
	}

	void cin_cl() {
		cin.seekg(0, ios::end);
		cin.clear();
	}

	char* protect_inp_ch(int len) {
		char* buf = new char[300]();
		cin_cl();
		cin.get(buf, 300);
		cin_cl();
		if (strlen(buf) == 0) {
			print("Строка пустая, повторите ввод: ");
			protect_inp_ch(len);
		}
		else if (strlen(buf) > len) {
			print("Превышено допустимое количество символов, повторите ввод: ");
			protect_inp_ch(len);
		}
		else if (buf[0] == '-' || buf[strlen(buf) - 1] == '-') {
			print("Введен недопустимый символ, повторите ввод: ");
			protect_inp_ch(len);
		}
		else {
			char* buf1 = new char[len]();
			for (int i = 0; i < len; i++) {
				buf1[i] = buf[i];
			}
			delete[] buf;
			return buf1;
		}
	}

	void Wait() {
		char temp[2];
		print("Нажмите ввод для продолжения...");
		cin_cl();
		cin.get(temp, 2);
		cin_cl();
	}

	virtual bool Edit() = 0;
};

class Student: virtual private Program {
	friend class File;
public:
	Student(){
		fam = new char[31]();
		name = new char[31]();
		otc = new char[31]();
		day = new int(0);
		month = new int(0);
		year = new int(0);
		priem_year = new int(0);
		gen = new char[2]();
		fac = new char[25]();
		kaf = new char[25]();
		group = new char[11]();
		book = new char[21]();
		book_new = new char[21];
	}

	~Student() {
		delete fam;
		delete name;
		delete otc;
		delete day;
		delete month;
		delete year;
		delete priem_year;
		delete fac;
		delete kaf;
		delete group;
		delete book;
	}

	bool Set() {
		print("Введите Фамилию {30}: ");
		if (!Set(fam, 31)) {
			return false;
		};
		
		print("Введите Имя {30}: ");
		Set(name, 31);

		print("Введите Отчество {30}: ");
		Set(otc, 31);

		print("Дата Рождения {dd.mm.yyyy}: ");
		while (!set_bd()) { 
			print("Дата Рождения {dd.mm.yyyy}: ");
		};

		print("Год Поступления {1900-2021}: ");
		Set_priem_year();

		print("Пол {[М/Ж]}: ");
		protection_gender();
		*(gen + 1) = '\0';

		print("Введите Факультет {25}: ");
		Set(fac, 25);

		print("Введите Кафедру {25}: ");
		Set(kaf, 25);

		print("Введите Группу {11}: "); 
		Set(group, 11);

		print("Введите Номер зачетной книжки {21}: ");
		Set(book, 21);
		cin_cl();
		while (!Check_book()) {
			print("Такой номер зачетной книжки уже существует\n");
			print("Введите Номер зачетной книжки {21}: ");
			Set(book, 21);
			cin_cl();
		}
		return true;
	}

	bool Edit() override {
		char* gbn_t;
		int ans;
		cin >> ans;
		if (ans != 11) print("Введите -1, чтобы вернуться назад\n");
		cin_cl();
		switch (ans) {
		case 1:
			print("Введите Фамилию {30}: ");
			Set(fam, 31);
			break;
		case 2:
			print("Введите Имя {30}: ");
			Set(name, 31);
			break;
		case 3:
			print("Введите отчество {30}: ");
			Set(otc, 31);
			break;
		case 4:
			print("Дата Рождения {dd.mm.yyyy}: ");
			while (!set_bd()) {
				print("Неверные данные, повторите ввод\n");
				print("Дата Рождения {dd.mm.yyyy}: ");
			};
			while (*priem_year - *year < 15) {
				print("Дата Рождения {dd.mm.yyyy}: ");
				while (!set_bd()) {
					print("Неверные данные, повторите ввод\n");
					print("Дата Рождения {dd.mm.yyyy}: ");
				};
			}
			break;
		case 5:
			print("Год Поступления {1900-2021}: ");
			Set_priem_year();
			break;
		case 6:
			print("Пол {[М/Ж]}: ");
			protection_gender();
			*(gen + 1) = '\0';
			break;
		case 7:
			print("Введите Факультет {25}: ");
			Set(fac, 25);
			break;
		case 8:
			print("Введите Кафедру {25}: ");
			Set(kaf, 25);
			break;
		case 9:
			print("Введите Группу {11}: ");
			Set(group, 11);
			break;
		case 10:
			gbn_t = new char[21];
			print("Введите Номер зачетной книжки {21}: ");
			while (Set(gbn_t, 21)) {
				if (!Check_book()) {
					if (strcmp(book, gbn_t)) {
						print("Такой номер зачетной книжки уже существует\n");
						print("Введите Номер зачетной книжки {21}: ");
					}
					else {
						book = gbn_t;
						break;
					}
				}
				else {
					break;
				}
				cin_cl();
			}
			break;
		case 11: return true;
		default: {
			print("Введен неверный вариант\n");
			Edit();
		}
		}
		return false;
	}

private:
	char* fam = nullptr;
	char* name = nullptr;
	char* otc = nullptr;
	int* day = nullptr;
	int* month = nullptr;
	int* year = nullptr;
	int* priem_year = nullptr;
	char* gen = nullptr;
	char* fac = nullptr;
	char* kaf = nullptr;
	char* group = nullptr;
	char* book = nullptr;
	char* book_new = nullptr;

	bool Set(char*& in, int len) {
		char* temp = protect_inp_ch(len);
		cin_cl();
		if (strcmp(temp, "В меню")) {
			in = temp;
			return true;
		}
		else return false;
	}

	bool set_bd() {
		char* temp = new char[11]();
		cin.get(temp, 11);
		cin_cl();
		if (!strcmp(temp, "-1")) {
			return true;
		}
		*day = 0;
		*month = 0;
		*year = 0;
		for (int i = 0; *(temp + i) != '\0'; i++) {
			if (*(temp + i) >= 48 && *(temp + i) <= 57 && ((i >= 0 && i <= 1) || (i >= 3 && i <= 4) || (i >= 6 && i <= 9))) {
				switch (i) {
				case 0: case 1:
					*day = *day * 10 + *(temp + i) - 0x30;
					break;
				case 3: case 4:
					*month = *month * 10 + *(temp + i) - 0x30;
					break;
				case 6: case 7: case 8: case 9:
					*year = *year * 10 + *(temp + i) - 0x30;
					break;
				}
			}
		}
		delete[] temp;
		if (check_date(*day, *month, *year)) return true;
		else return false;
	}

	void Set_priem_year() {
		int temp;
		cin >> temp;
		if (temp == -1) {
			return;
		}
		*priem_year = temp;
		while (*priem_year <= *year || *priem_year - *year < 15 || *priem_year - *year > 115 || *priem_year - *year >  85 || (*priem_year <= 1900 || *priem_year >= 2021)) {
			if (*priem_year <= *year) print("Год поступления не может равняться или быть меньше года рождения \n");
			else if (*priem_year - *year < 15) print("Студент не может поступить в университет раньше 15 лет \n");
			else if (*priem_year - *year > 100) print("Студент не может поступить в университет после 100 лет \n");
			else if (*priem_year <= 1900 || *priem_year >= 2021) print("Неверные данные! Повторите ввод \n");
			else break;
			print("Год Поступления {1900-2021}: ");
			cin >> *priem_year;
		}
	}

	bool Check_book() {
		int* len = new int(0);
		int* len_file = new int(0);
		char* buf = new char[21];
		Crypto crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(PATH, ios::binary);

		File.seekg(0, ios::end);
		*len_file = File.tellg();
		File.seekg(0, ios::beg);

		while (*len != *len_file) {
			File.seekg(171, ios::cur);
			File.read(buf, 21);

			if (!strcmp(buf, book)) {
				File.close();
				crypt.Encrypt();
				return false;
			}

			int* session_count = new int(0);
			int* subject_count = new int(0);
			int* sum = new int(0);

			File.read((char*)&*session_count, 4);


			for (int i = 0; i < *session_count; i++) {
				File.read((char*)subject_count, 4);
				*sum = *sum + *subject_count;
			}
			File.seekg((*sum) * 25, ios::cur);


			*len = *len + 171;
			*len = *len + 21;
			*len = *len + 4;
			*len = *len + *session_count * 4;
			*len = *len + (*sum) * 25;
		}
		File.close();
		crypt.Encrypt();
		return true;
		
	}

	bool check_date(int day, int month, int year) {
		if (day != 0 && month != 0 && year != 0) {
			if (year >= 1900 && year <= 2021) {
				if (month >= 1 && month <= 12) {
					switch (month) {
					case 1: case 3: case 5: case 7: case 8: case 10: case 12:
						if (day >= 1 && day <= 31) {
							return true;
						}
						break;
					case 2:
						if (year % 4 != 0 || year % 100 == 0 && year % 400 != 0) {
							if (day >= 1 && day <= 28) {
								return true;
							}
						}
						else {
							if (day >= 1 && day <= 29) {
								return true;
							}
						}
						break;
					case 4: case 6: case 9: case 11:
						if (day >= 1 && day <= 30) {
							return true;
						}
						break;
					default:
						print("ERROR - Введена неверная дата\n");
					}

				}
				else {
					print("ERROR - Месяц должен быть от 1 до 12\n");
				}
			}
			else {
				print("ERROR - Год должен быть от 1900 до 2021\n");
			}
		}
		return false;
	}

	void protection_gender() {
		char value[3];
		while (true) {
			cin >> value;
			cin_cl();
			if (!strcmp((char*)value, "-1")) {
				return;
			}
			if (!strcmp(value,"М") || !strcmp(value, "Ж") || !strcmp(value, "F") || !strcmp(value, "M") || !strcmp(value, "m") || !strcmp(value, "ж") || !strcmp(value, "м") || !strcmp(value, "f")) {
				cin_cl();
				*gen = *value;
				return;
			}
			print("Не верные данные! Пожалуйста вводите только М(M) для Юношей или Ж(F) для Девушек! \n");
			cin_cl();
		}
	}

};

class Session: virtual private Program {
	friend class File;
public:
	Session() {
		session_count = new int(0);
		sub_count = nullptr;
	}
	
	~Session() {
		delete session_count;
		delete sub_count;
		delete subject;
	}

	void Set_session() {
		Set_session_count();
		Set_sub_count();
		Set_sub();
	}

	bool Edit() override {
		int sub_sum = 0;
		for (int i = 0; i < *session_count; i++) {
			sub_sum = sub_sum + *(sub_count + i);
		}
		int pos = -1;
		Sub* temp = nullptr;
		int* temp_2 = nullptr;
		int sum = 0;
		int ans, num = -1, ses;
		cin >> ans;
		cin_cl();
		if (ans == 1) {
			if (*session_count < 9) {
				system("cls");
				int sub_new = 0;
				print("Введите количество предметов в новой сессии: ");
				cin >> sub_new;
				cin_cl();
				int sub_sum = 0;
				for (int i = 0; i < *session_count; i++) {
					sub_sum = sub_sum + *(sub_count + i);
				}

				temp = new Sub[sub_sum + sub_new]();
				*session_count = *session_count + 1;
				temp_2 = new int[*session_count]();

				for (int i = 0; i < sub_sum; i++) {
					for (int j = 0; j < 31; j++) {
						*((temp + i)->name + j) = *((subject + i)->name + j);
					}
					*((temp + i)->mark) = *((subject + i)->mark);
				}

				for (int i = sub_sum; i < sub_sum + sub_new; i++) {
					print("Введите название ");
					print(i - sub_sum + 1);
					print(" предмета в новой сессии: ");
					(temp + i)->name = protect_inp_ch(21);
					print("Оценка {[2-5]}: ");
					int buf;
					while (true) {
						cin_cl();
						cin >> buf;
						cin_cl();
						if (buf >= 2 && buf <= 5) {
							*((temp + i)->mark) = buf;
							break;
						}
						print("Не верные данные! Вводите значения от 2 до 5\n");
					}
				}

				for (int i = 0; i < *session_count - 1; i++) {
					*(temp_2 + i) = *(sub_count + i);
				}

				*(temp_2 + *session_count - 1) = sub_new;

				delete[] subject;
				delete[] sub_count;

				*&subject = temp;
				*&sub_count = temp_2;
			}
			else {
				print("Максимальное количество сессий\n");
				Wait();
			}
		}
		else if (ans == 2 || ans == 3 || ans == 4) {
			print("Введите номер сессии >> ");
			cin >> ses;
			if (!(ses != 0 && ses <= *session_count)) {
				print("Номер такой сессии не найден, повторите ввод\n");
				Wait();
				return false;
			}
			ses -= 1;
			if (ans == 2 || ans == 4)
			{
				print("Введите номер предмета >> ");
				cin >> num;
				if (!(num <= *(sub_count + ses) && num != 0)) {
					print("Номер такого предмета не найден, повторите ввод\n");
					Wait();
					return false;
				}
				num -= 1;
			}
			if (ans == 3) {
				if (*(sub_count + ses) == 10) {
					print("Нельзя добавить предмет, максимальное количество\n");
					Wait();
					return false;
				}
				temp = new Sub[sub_sum + 1]();
			}
			else if (ans == 4) temp = new Sub[sub_sum - 1]();

			system("cls");
			int sum_new = 0;
			for (int i = 0; i < *session_count; i++) {
				for (int j = 0; j < *(sub_count + i); j++) {
					if (((!(ses == i && num == j) || ans != 4) && ans != 2) || (ans == 3 && num == -1)) {
						for (int k = 0; k < 21; k++) {
							*((temp + sum_new)->name + k) = *((subject + sum)->name + k);
						}
						*((temp + sum_new)->mark) = *((subject + sum)->mark);
						sum_new++;
					}
					else if (i == ses && j == num && ans == 2) {
						print("Выбранный предмет: ");
						cout << (subject + sum)->name << " Оценка: " << *(subject + sum)->mark << "\n";
						print("Что нужно изменить: 1 - Название предмета, 2 - Оценку по предмету, 3 - Вернуться назад\n");
						print(">> ");
						cin >> ans;
						switch (ans) {
						case 1:
							print("Название предмета {20}: ");
							(subject + sum)->name = protect_inp_ch(21);
							break;
						case 2:
							print("Оценка {[2-5]}: ");
							int buf;
							while (true) {
								cin_cl();
								cin >> buf;
								cin_cl();
								if (buf >= 2 && buf <= 5) {
									*(subject + sum)->mark = buf;
									break;
								}
								print("Не верные данные! Вводите значения от 2 до 5\n");
							}
							break;
						case 3:
							return false;
						}
					}
					if (ans == 3 && ses == i && j+1 == *(sub_count + i)) {
						print("Название предмета {20}: ");
						(temp + sum_new)->name = protect_inp_ch(21);
						cin_cl();
						print("Оценка {[2-5]}: ");
						int buf;
						while (true) {
							cin_cl();
							cin >> buf;
							cin_cl();
							if (buf >= 2 && buf <= 5) {
								*(temp + sum_new)->mark = buf;
								break;
							}
							print("Не верные данные! Вводите значения от 2 до 5\n");
						}
						sum_new++;
					}
					sum++;
				}}

			if (ans == 4) {
				*(sub_count + ses) = *(sub_count + ses) - 1;
				if (*(sub_count + ses) == 0) {
					sum = 0;
					*session_count = *session_count - 1;
					int* temp_1 = new int[*session_count];
					for (int i = 0; i <= *session_count + 1; i++) {
						if (i != ses) {
							*(temp_1 + sum) = *(sub_count + i);
							sum++;
						}
					}
					delete[] sub_count;
					sub_count = temp_1;
				}
			}
			else if (ans == 3) {
				*(sub_count + ses) = *(sub_count + ses) + 1;
			}
			if (ans == 3 || ans == 4) {
				delete[] subject;
				subject = temp;
			}
		}
		else if (ans == 5) {
			return true;
		}
		else {
			print("Такого варианта не найдено\n");
			Wait();
			return false;
		}
		return false;
	}

private:
	int* session_count = nullptr;
	int* sub_count = nullptr;
	Sub* subject = nullptr;

	void Set_session_count() {
		print("Количество семестров {1-9}: ");
		int value;
		while (true) {
			cin >> value;
			cin_cl();
			if (value >= 1 && value <= 9) {
				*session_count = value;
				break;
			}
			print("Не верные данные! Вводите значения от 1 до 9 \n");
		}
	}

	void Set_sub_count() {
		sub_count = new int[*session_count];
		bool flag = true;
		for (int i = 0; i < *session_count; i++) {
			bool flag = true;
			print("Введите количество предметов в ");
			print(i + 1);
			print(" семестре {1-10}: ");
			while (flag) {
				int* buf = new int();
				cin >> *buf;
				cin_cl();
				if (*buf >= 1 && *buf <= 10) {
					*(sub_count + i) = *buf;
					flag = false;
				}
				else {
					print("Не верные данные! Вводите значения от 1 до 9 \n");
				}
			}
		}
	}

	void Set_sub() {
		int* sum = new int(0);
		for (int i = 0; i < *session_count; i++) {
			*sum = *sum + *(sub_count + i);
		}
		subject = new Sub[*sum];
		int* session_num = new int(0);
		int* subject_num = new int(0);
		for (int i = 0; i < *sum; i++) {
			if (*subject_num >= sub_count[*session_num]) {
				(*session_num)++;
				*subject_num = 0;
			}
			(*subject_num)++;
			(subject + i)->mark = new int(0);
			print("Cессия ");
			print(*session_num + 1);
			print(" предмет ");
			print(*subject_num);
			print(" название предмета {20}: ");
			(subject + i)->name = protect_inp_ch(21);
			cin_cl();
			print("Cессия ");
			print(*session_num + 1);
			print(" предмет ");
			print(*subject_num);
			print(" оценка {[2-5]}: ");
			int buf;
			while (true) {
				cin_cl();
				cin >> buf;
				cin_cl();
				if (buf >= 2 && buf <= 5) {
					*(subject + i)->mark = buf;
					break;
				}
				print("Не верные данные! Вводите значения от 2 до 5\n");
			}
		}
		delete sum;
		delete session_num;
		delete subject_num;
	}

};

class File : virtual private Program {
public:

	File() {
		length = new int(0);
		len = new int(0);
		pos = new int(0);
		count = new int(0);
		sum = new int(0);
		gbn_t = new char[21]();
	}

	~File() {
		delete length;
		delete count;
		delete sum;
	}

	void Add_student() {
		Student* student = new Student;
		Session* session = new Session;
		if (!student->Set()) {
			delete student;
			delete session;
			return;
		}
		session->Set_session();

		Crypto crypt;
		crypt.Decrypt();

		ofstream file(PATH, ios::binary | ios::app);

		file.write(student->fam, 31);
		file.write(student->name, 31);
		file.write(student->otc, 31); 
		file.write((char*)student->day, 4);
		file.write((char*)student->month, 4);
		file.write((char*)student->year, 4);
		file.write((char*)student->gen, 1);
		file.write((char*)student->priem_year, 4);
		file.write(student->fac, 25);
		file.write(student->kaf, 25);
		file.write(student->group, 11);
		file.write(student->book, 21);

		file.write((char*)session->session_count, 4);

		for (int i = 0; i < *session->session_count; i++) {
			file.write((char*)(&*(session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *session->session_count; i++) {
			*sum = *sum + *(session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			file.write((char*)(session->subject+i)->name, 21);
			file.write((char*)(session->subject + i)->mark, 4);
		}

		delete student;
		delete session;
		file.close();

		crypt.Encrypt();
	}

	bool Edit() override{
		ofstream test("Students.new.txt", ios::binary);
		test.close();
		Crypto crypt;
		int ans;
		int ans_2;
		if(!Stud_count()) return false;
		system("cls");
		print("Редактирования информации о студенте\n\n");
		Print_students(1, false);
		while (!find_student()) {
			print("Такой студент не найден\n");
			print("1 - Ввести другой номер зачетной книжки\n");
			print("2 - Назад\n");
			print(">> ");
			cin >> ans_2;
			while (ans_2 != 1 && ans_2 != 2) {
				print("1 - Ввести другого студента\n");
				print("2 - Назад\n");
				print(">> ");
				cin >> ans_2;
			}
			if (ans_2 == 2) return false;
		}
		if (*pos == -1) {
			return false;
		}
		bool flag = true;
		while (flag) {
			print("1 - Редактировать сведения о студенте\n");
			print("2 - Редактировать данные о сессии студента\n");
			print("3 - Назад\n>> ");
			cin >> ans;
			len = new int(0);
			for (int i = 0; i < *count; i++) {
				Read_student();
				if (i != *pos) {
					Write_NewFile();
				}
				else {
					switch (ans) {
					case 1:
						while (true) {
							system("cls");
							print_v(2);
							print("Редактирования информации о студенте\n");
							print("1 - Редактировать фамилию студента\n");
							print("2 - Редактировать имя студента\n");
							print("3 - Редактировать отчество студента\n");
							print("4 - Редактировать дату рождения студента\n");
							print("5 - Редактировать год приема студента в университет\n");
							print("6 - Редактировать пол студента\n");
							print("7 - Редактировать факультет студента\n");
							print("8 - Редактировать кафедру студента\n");
							print("9 - Редактировать группу студента\n");
							print("10 - Редактировать номер зачетной книжки студента\n");
							print("11 - Сохранить изменения\n");
							print(">> ");
							if (edit_student->Edit()) {
								break;
							}
						}
						break;
					case 2:
						while (true) {
							system("cls");
							print("Редактирования информации о сессии студента\n");
							print_v(1);
							print_v(3);
							print("1 - Добавить сессию\n");
							print("2 - Редактировать информацию о предметах студента\n");
							print("3 - Добавить предмет\n");
							print("4 - Удалить предмет\n");
							print("5 - Сохранить изменения\n");
							print(">> ");
							if (edit_session->Edit()) {
								break;
							};
						}
						break;
					case 3:
						flag = false;
						break;
					default:
						if (remove("Students.new.txt") != 0) {
							print("ERROR -- ошибка при удалении файла\n");
							Wait();
						}
						print("Такого варианта не найдено\n");
						Wait();
						break;
					}
					Write_NewFile();
					delete edit_student;
					delete edit_session;
				}
			}
			if (remove("Students.txt.enc") != 0) {
				print("ERROR -- ошибка при удалении файла\n");
				Wait();
			}
			if (rename("Students.new.txt", PATH) != 0) {
				print("ERROR -- ошибка при переименовании файла\n");
				Wait();
			}
			else {
				crypt.Encrypt();
			}
			delete len;
			flag = false;
		}
		delete pos;
		delete gbn_t;
	}

	void Delete_student() {
		Crypto crypt;
		if (!Stud_count()) return;
		*pos = -1;
		Print_students(1, false);
		print("Введите номер зачетной книжки('В меню' чтобы вернуться назад) >> ");
		cin_cl();
		len = new int(0);
		gbn_t = protect_inp_ch(21);
		cin_cl();
		if (!strcmp(gbn_t, "В меню")) {
			return;
		}

		for (int i = 0; i < *count; i++) {
			Read_student();
			if (!strcmp(gbn_t, edit_student->book)) {
				*pos = i;
				break;
			}
			delete edit_student;
			delete edit_session;
		}

		if (*pos != -1) {
			*len = 0;
			for (int i = 0; i < *count; i++) {
				Read_student();
				if (i != *pos) {
					Write_NewFile();
				}
				delete edit_student;
				delete edit_session;
			}
			*count -= 1;
			if (remove("Students.txt.enc") != 0) {
				print("ERROR -- ошибка при удалении файла\n");
				Wait();
			};
			if (*count == 0) {
				return;
			}
			if (rename("Students.new.txt", PATH) != 0) {
				print("ERROR -- ошибка при переименовании файла\n");
				Wait();
			}
			else {
				crypt.Encrypt();
			}
		}
		else {
			print("Такой студент не найден\n");
			Delete_student();
		}

		delete pos;
		delete gbn_t;
	}

	void Print_students(int rez, bool Task) {
		if (!Stud_count()) return;
		len = new int(0);
		gbn_t = new char[21];
		int ans_2;
		if (rez == 5) {
			Print_students(1, false);
			while (!find_student()) {
				print("Такой студент не найден\n");
				print("1 - Ввести другой номер зачетной книжки\n");
				print("2 - Назад\n");
				print(">> ");
				cin >> ans_2;
				while (ans_2 != 1 && ans_2 != 2) {
					print("1 - Ввести другого студента\n");
					print("2 - Назад\n");
					print(">> ");
					cin >> ans_2;
				}
				if (ans_2 == 2) return;
			}
			if (*pos == -1) {
				return;
			}
		}
		len = new int(0);
		for (int i = 0; i < *count; i++) {
			Read_student();
			if (!Task) {
				switch (rez) {
				case 1:
					print_v(1);
					break;
				case 2:
					print_v(2);
					break;
				case 3:
					print_v(1);
					print_v(3);
					line;
					break;
				case 4:
					print_v(2);
					print_v(3);
					line;
					break;
				case 5:
					if (i == *pos) {
						system("cls");
						print_v(2);
						print_v(3);
						line;
					}
					break;
				}
			}
			else {
				if (Check_mark()) {
					print_v(2);
					print_v(3);
					line;
				}
			}
			delete edit_student;
			delete edit_session;
		}
		delete len;
	}

private:
	Student* edit_student = nullptr;
	Session* edit_session = nullptr;
	int* length;
	int* len;
	int* pos;
	int* count;
	int* sum;
	char* gbn_t;

	bool find_student() {
		*pos = -1;
		len = new int(0);
		print("Введите номер зачетной книжки('В меню' чтобы вернуться обратно) >> ");
		cin_cl();
		gbn_t = protect_inp_ch(21);
		cin_cl();

		if (!strcmp(gbn_t, "В меню")) {
			return true;
		}

		for (int i = 0; i < *count; i++) {
			Read_student();
			if (!strcmp(gbn_t, edit_student->book)) {
				*pos = i;
				delete edit_student;
				delete edit_session;
				delete len;
				return true;
			}
			delete edit_student;
			delete edit_session;
		}
		delete len;
		return false;
	}

	void Read_student() {
		Crypto crypt;
		crypt.Decrypt();

		ifstream File;
		File.open(PATH, ios::binary);

		File.seekg(0, ios::end);
		*length = File.tellg();
		File.seekg(*len, ios::beg);
		if (*len != *length) {
			edit_student = new Student();
			edit_session = new Session();

			File.read(edit_student->fam, 31);
			File.read(edit_student->name, 31);
			File.read(edit_student->otc, 31); 
			File.read((char*)edit_student->day, 4);
			File.read((char*)edit_student->month, 4);
			File.read((char*)edit_student->year, 4);
			File.read(edit_student->gen, 1);
			File.read((char*)edit_student->priem_year, 4);
			File.read(edit_student->fac, 25);
			File.read(edit_student->kaf, 25);
			File.read(edit_student->group, 11);
			File.read(edit_student->book, 21);

			File.read((char*)edit_session->session_count, 4);

			edit_session->sub_count = new int[*edit_session->session_count];
			*sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				File.read((char*)(&*(edit_session->sub_count + i)), 4);
				*sum = *sum + *(edit_session->sub_count + i);
			}

			edit_session->subject = new Sub[*sum]();

			for (int i = 0; i < *sum; i++) {
				File.read((char*)(edit_session->subject + i)->name, 21);
				File.read((char*)(edit_session->subject + i)->mark, 4);
			}
			*len = *len + 192;
			*len = *len + 4;
			*len = *len + *edit_session->session_count * 4;
			*len = *len + *sum * 25;
		}
		File.close();
		crypt.Encrypt();
	}

	void Write_NewFile() {
		char newname[] = "Students.new.txt";
		ofstream FILE_NEW;
		FILE_NEW.open(newname, ios::binary | ios::app);

		FILE_NEW.write(edit_student->fam, 31);
		FILE_NEW.write(edit_student->name, 31);
		FILE_NEW.write(edit_student->otc, 31); 
		FILE_NEW.write((char*)edit_student->day, 4);
		FILE_NEW.write((char*)edit_student->month, 4);
		FILE_NEW.write((char*)edit_student->year, 4);
		FILE_NEW.write((char*)edit_student->gen, 1);
		FILE_NEW.write((char*)edit_student->priem_year, 4);
		FILE_NEW.write(edit_student->fac, 25);
		FILE_NEW.write(edit_student->kaf, 25);
		FILE_NEW.write(edit_student->group, 11);
		FILE_NEW.write(edit_student->book, 21);

		FILE_NEW.write((char*)edit_session->session_count, 4);

		for (int i = 0; i < *edit_session->session_count; i++) {
			FILE_NEW.write((char*)(&*(edit_session->sub_count + i)), 4);
		}
		*sum = 0;
		for (int i = 0; i < *edit_session->session_count; i++) {
			*sum = *sum + *(edit_session->sub_count + i);
		}
		for (int i = 0; i < *sum; i++) {
			FILE_NEW.write((char*)(edit_session->subject + i)->name, 21);
			FILE_NEW.write((char*)(edit_session->subject + i)->mark, 4);
		}
		FILE_NEW.close();
	}

	bool Stud_count() {
		fstream file("Students.txt.enc", ios::binary | ios::in);
		file.seekg(0, ios::end);
		if (file.tellg() == -1 || file.tellg() == 0) {
			file.close();
			print("Файл пустой, доступна только функция добавления студентов\n");
			return false;
		}
		file.close();

		Crypto* crypt = new Crypto;
		crypt->Decrypt();

		ifstream File;
		File.open(PATH, ios::binary);

		*len = 0;
		*count = 0;
		File.seekg(0, ios::end);
		*length = File.tellg();
		File.seekg(0, ios::beg);

		while (*length != *len) {
			File.seekg(192, ios::cur);
			*len = *len + 192;

			int* session_count = new int(0);
			int* subject_count = new int(0);

			File.read((char*)&*session_count, 4);
			*len = *len + 4;

			*len = *len + *session_count * 4;
			*sum = 0;
			for (int i = 0; i < *session_count; i++) {
				File.read((char*)&*subject_count, 4);
				*sum = *sum + *subject_count;
			}
			File.seekg((*sum * 25), ios::cur);
			*len = *len + (*sum * 25);
			(*count)++;
		}
		File.close();

		crypt->Encrypt();

		return true;
	}

	void print_v(int rez) {
		switch (rez) {
		case 1:
			cout << "ФИО: " << edit_student->fam << " " << edit_student->name << " " << edit_student->otc << "\n";
			cout << "Номер зачетной книжки: " << edit_student->book << "\n\n";
			break;
		case 2:
			cout << "ФИО: " << edit_student->fam << " " << edit_student->name << " " << edit_student->otc << "\n";
			cout << "Дата рождения: " << *edit_student->day << "." << *edit_student->month << "." << *edit_student->year << " Год приема: " << *edit_student->priem_year << "\n";
			cout << "Пол: " << edit_student->gen << " Факультет: " << edit_student->fac << " Кафедра: " << edit_student->kaf << " Группа: " << edit_student->group << "\n";
			cout << "Номер зачетной книжки: " << edit_student->book << "\n\n";
			break;
		case 3:
			int sum = 0;
			for (int i = 0; i < *edit_session->session_count; i++) {
				cout << "Cессия " << i + 1 << "\n";
				for (int j = 0; j < *((edit_session->sub_count) + i); j++) {
					cout << j + 1 << "." << ((edit_session->subject) + sum)->name << " " << *(((edit_session->subject) + sum)->mark) << "\n";
					sum++;
				}
				cout << "\n";
			}
			break;
		}
	}

	bool Check_mark() {
		int sum = 0;
		for (int i = 0; i < *edit_session->session_count; i++) {
			for (int j = 0; j < *(edit_session->sub_count + i); j++) {
				if (*((edit_session->subject + sum)->mark) == 3) {
					return false;
				}
				sum++;
			}
		}
		return true;
	}
};

class Menu : virtual private Program {
public:
	Menu() {
		ans = new int;
		SetConsoleCP(1251);
		SetConsoleOutputCP(1251);
		system("cls");
		file = new File;
	}

	~Menu() {
		delete file;
		delete ans;
	}

	bool hub() {
		file = new File;
		system("cls");
		print("Выберите вариант\n");
		print("1 - Добавить студента\n");
		print("2 - Удалить студента\n");
		print("3 - Изменить данные студента\n");
		print("4 - Вывести всю базу студентов\n");
		print("5 - Вывести всех студентов, не имеющих оценки 3\n");
		print("6 - Выйти из программы\n");
		print(" >>>> ");
		cin >> *ans;
		cin_cl();
		switch (*ans) {
		case 1: {
			system("cls");
			print("Добавление нового студента(Введите 'В меню', чтобы вернуться назад)\n");
			file->Add_student();
			Wait();
			break;
		}
		case 2: {
			system("cls");
			print("Удаление студента\n");
			file->Delete_student();
			Wait();
			break;
		}
		case 3: {
			this->Edit();
			Wait();
			break;
		}
		case 4: {
			system("cls");
			print("Вывод всех студентов\n");
			print("1 - Вывод всей информации\n");
			print("2 - Вывод части информации\n");
			print("3 - Вывод информации о конкретном студенте\n");
			print("4 - Назад\n");
			print(">>> ");
			cin >> *ans;
			switch (*ans) {
			case 1: {
				file->Print_students(4, false);
				Wait();
				break;
			}
			case 2:
			{
				file->Print_students(2, false);
				Wait();
				break;
			}
			case 3:
				file->Print_students(5, false);
				Wait();
				break;
			case 4:
				break;
			}
			break;
		}
		case 5:
			system("cls");
			print("Вывод всех студентов, не имеющих оценки 3\n");
			file->Print_students(4, true);
			Wait();
			break;
		case 6:
			return false;
		}
		return true;
		delete file;
	}

private:
	File* file = nullptr;
	int* ans = nullptr;
	bool Edit() override { file->Edit(); return true; }
};

int main() {
	Menu* menu = new Menu();
	while (menu->hub());
	delete menu;
	
	return 0;
}